import json
from channels.generic.websocket import AsyncWebsocketConsumer
from base64 import b64decode


class RbacConsumer(AsyncWebsocketConsumer):
    @staticmethod
    def channel_group_name(account_number):
        return f"account_{account_number}"

    async def connect(self):
        headers = self.scope.get("headers", [])
        identity_header = next((val for key, val in headers if key.decode("utf-8") == "x-rh-identity"), {})
        decoded_identity_header = b64decode(identity_header)
        json_identity_header = json.loads(decoded_identity_header)
        self.account_number = json_identity_header.get("identity", {})["account_number"]
        self.channel_group_name = RbacConsumer.channel_group_name(self.account_number)
        await self.channel_layer.group_add(self.channel_group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.channel_group_name, self.channel_name)

    async def receive(self, text_data):
        pass

    async def cross_account_request_update(self, event):
        message = event["message"]
        await self.send(text_data=json.dumps({"message": message}))
