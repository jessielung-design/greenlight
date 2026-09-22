# frozen_string_literal: true

module Api
  module V1
    # Instance-scoped server-to-server adapter. Never accepts browser sessions.
    # Meeting status reuses Greenlight's access-code, guest and start policies.
    class EbramController < MeetingsController
      skip_before_action :ensure_valid_request, :ensure_authenticated
      skip_forgery_protection
      prepend_before_action :authenticate_ebram
      before_action :authorize_ebram_room, only: %i[show status]

      def index
        page = Integer(params.fetch(:page, 1), exception: false)
        size = Integer(params.fetch(:page_size, 20), exception: false)
        return render_error status: :bad_request unless page&.positive? && size&.between?(1, 100)

        rooms = Room.includes(:user).with_provider(current_provider)
        unless PermissionsChecker.new(current_user:, current_provider:, permission_names: 'ManageRooms').call
          rooms = rooms.where(user_id: current_user.id).or(rooms.where(id: current_user.shared_rooms.select(:id)))
        end
        render json: { data: rooms.order(:id).offset((page - 1) * size).limit(size).map { |room| room_data(room) } }
      end

      def show
        render json: { data: room_data(@room) }
      end

      # Guest policy denials are distinct from invalid integration credentials.
      def render_error(data: nil, errors: [], status: :bad_request)
        status = :forbidden if status == :unauthorized && @ebram_authenticated
        super
      end

      def current_user
        @ebram_user
      end

      def current_provider
        ENV.fetch('EBRAM_PROVIDER', 'greenlight')
      end

      private

      def authenticate_ebram
        key = ENV['EBRAM_API_KEY'].to_s
        org = ENV['EBRAM_ORGANIZATION_ID'].to_s
        provided = request.headers['Authorization'].to_s
        unless key.length >= 32 && org.present? &&
               ActiveSupport::SecurityUtils.secure_compare("Bearer #{key}", provided) &&
               request.headers['X-Ebram-Organization'] == org
          return render_error status: :unauthorized
        end

        @ebram_authenticated = true
        user_id = request.headers['X-Ebram-User-ID']
        if action_name == 'status' && params[:guest] == true && user_id.blank?
          return
        end

        @ebram_user = User.find_by(id: user_id, provider: current_provider)
        render_error status: :forbidden unless @ebram_user&.active?
      end

      def authorize_ebram_room
        @room ||= Room.includes(:user).with_provider(current_provider).find_by!(friendly_id: params[:friendly_id])
        if action_name == 'status'
          return render_error status: :forbidden unless params[:meeting_id] == @room.meeting_id
          return if params[:guest] == true && current_user.nil?
        end

        ensure_authorized(%w[ManageRooms SharedRoom], friendly_id: @room.friendly_id)
      end

      def room_data(room)
        { id: room.id, friendly_id: room.friendly_id, meeting_id: room.meeting_id, name: room.name }
      end

      # No persistent guest cookies on a backend-to-backend request.
      def fetch_bbb_user_id
        current_user ? "gl-#{current_user.id}" : "gl-guest-#{SecureRandom.hex(12)}"
      end
    end
  end
end
