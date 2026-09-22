# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Api::V1::EbramController, type: :controller do
  let(:user) { create(:user) }
  let(:room) { create(:room, user:) }
  let(:key) { 'a' * 32 }

  before do
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with('EBRAM_API_KEY').and_return(key)
    allow(ENV).to receive(:[]).with('EBRAM_ORGANIZATION_ID').and_return('org-a')
    request.headers['Authorization'] = "Bearer #{key}"
    request.headers['X-Ebram-Organization'] = 'org-a'
    request.headers['X-Ebram-User-ID'] = user.id
    request.headers['Accept'] = 'application/json'
  end

  it 'rejects a valid key used for a different organisation' do
    request.headers['X-Ebram-Organization'] = 'org-b'
    get :index, format: :json
    expect(response).to have_http_status(:unauthorized)
  end

  it 'does not accept a browser session in place of the integration key' do
    sign_in_user(user)
    request.headers.delete('Authorization')
    get :index, format: :json
    expect(response).to have_http_status(:unauthorized)
  end

  it 'is disabled without an integration key' do
    allow(ENV).to receive(:[]).with('EBRAM_API_KEY').and_return(nil)
    get :index, format: :json
    expect(response).to have_http_status(:unauthorized)
  end

  it 'rejects banned users' do
    user.update!(status: :banned)
    get :index, format: :json
    expect(response).to have_http_status(:forbidden)
  end

  it 'returns only owned and shared rooms with the original BBB ID' do
    other = create(:room)
    shared = create(:room)
    create(:shared_access, user:, room: shared)
    room
    get :index, format: :json
    expect(response).to have_http_status(:ok)
    data = response.parsed_body['data']
    expect(data.pluck('friendly_id')).to contain_exactly(room.friendly_id, shared.friendly_id)
    expect(data.pluck('friendly_id')).not_to include(other.friendly_id)
    expect(data.find { |entry| entry['id'] == room.id }['meeting_id']).to eq(room.meeting_id)
  end

  it 'rejects an unshared room even if the caller knows its ID' do
    other = create(:room)
    get :show, params: { friendly_id: other.friendly_id }, format: :json
    expect(response).to have_http_status(:forbidden)
  end

  it 'rejects invalid pagination' do
    get :index, params: { page_size: 101 }, format: :json
    expect(response).to have_http_status(:bad_request)
  end

  it 'rejects a replaced BBB meeting mapping before attempting to join' do
    expect(BigBlueButtonApi).not_to receive(:new)
    post :status, params: { friendly_id: room.friendly_id, meeting_id: 'other' }, as: :json
    expect(response).to have_http_status(:forbidden)
  end

  it 'reuses Greenlight moderator roles for the room owner' do
    allow_any_instance_of(BigBlueButtonApi).to receive(:meeting_running?).and_return(true)
    expect_any_instance_of(BigBlueButtonApi).to receive(:join_meeting)
      .with(room:, name: user.name, user_id: "gl-#{user.id}", avatar_url: nil, role: 'Moderator')
      .and_return('https://bbb.example/join')
    post :status, params: { friendly_id: room.friendly_id, meeting_id: room.meeting_id }, as: :json
    expect(response).to have_http_status(:ok)
    expect(response.parsed_body.dig('data', 'joinUrl')).to eq('https://bbb.example/join')
  end

  it 'keeps require-authentication effective for invited guests' do
    request.headers.delete('X-Ebram-User-ID')
    allow_any_instance_of(RoomSettingsGetter).to receive(:call).and_return('glRequireAuthentication' => 'true')
    expect(BigBlueButtonApi).not_to receive(:new)
    post :status, params: { friendly_id: room.friendly_id, meeting_id: room.meeting_id, guest: true, name: 'Guest' }, as: :json
    expect(response).to have_http_status(:forbidden)
  end

  it 'requires viewer access codes for guests' do
    request.headers.delete('X-Ebram-User-ID')
    allow_any_instance_of(RoomSettingsGetter).to receive(:call).and_return('glViewerAccessCode' => 'secret')
    post :status, params: { friendly_id: room.friendly_id, meeting_id: room.meeting_id, guest: true, name: 'Guest' }, as: :json
    expect(response).to have_http_status(:forbidden)
  end
end
