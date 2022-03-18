"""Consumers for rbac."""
import json
from base64 import b64decode

from channels.generic.websocket import AsyncWebsocketConsumer


class RbacConsumer(AsyncWebsocketConsumer):
    """Consumer for websockets in rbac app."""

    @staticmethod
    def channel_group_name(account_number):
        """Return the channel group name for an account."""
        return f"account_{account_number}"

    async def connect(self):
        """Establish a websocket connection."""
        headers = self.scope.get("headers", [])
        identity_header = next((val for key, val in headers if key.decode("utf-8") == "x-rh-identity"), {})
        decoded_identity_header = b64decode(identity_header)
        json_identity_header = json.loads(decoded_identity_header)
        self.account_number = json_identity_header.get("identity", {})["account_number"]
        self.channel_group_name = RbacConsumer.channel_group_name(self.account_number)
        await self.channel_layer.group_add(self.channel_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        """Discard channel groups on disconnect."""
        await self.channel_layer.group_discard(self.channel_group_name, self.channel_name)

    async def receive(self, text_data):
        """No-op receiving messages."""
        pass

    async def cross_account_request_update(self, event):
        """Establish async event for cross account request updates."""
        message = event["message"]
        await self.send(text_data=json.dumps({"message": message}))
