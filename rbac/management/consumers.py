import json
from channels.generic.websocket import AsyncWebsocketConsumer
from base64 import b64decode


class RbacConsumer(AsyncWebsocketConsumer):
    # Execute from within code
    # from channels.layers import get_channel_layer
    # from asgiref.sync import async_to_sync
    # channel_layer = get_channel_layer()
    #
    # async_to_sync(channel_layer.group_send)("account_1234", {"type": "tam_update","message": "pong!"})

    @staticmethod
    def channel_group_name(account_number):
        return f"account_{account_number}"

    async def connect(self):
        # MOCK THE IDENTITY
        # from base64 import b64encode
        # from json import dumps as json_dumps
        # import random

        # account_numbers = ["1234", "5678"]
        # account_number = random.choice(account_numbers)
        # connection_message = f"**** SETTING UP CONNECTION FOR ACCOUNT: {account_number} ****"
        # print(connection_message)
        # raw_identity_header = {
        #     "identity": {
        #         "account_number": account_number,
        #             "type": "User",
        #             "user": {
        #                 "username": "user_dev",
        #                   "email": "user_dev@foo.com",
        #                   "is_org_admin": True,
        #                   "is_internal": True,
        #                   "user_id": "51736777",
        #         },
        #         "internal": {
        #             "cross_access": False
        #         },
        #     }
        # }
        # json_identity = json_dumps(raw_identity_header)
        # identity_header = b64encode(json_identity.encode("utf-8"))
        # MOCK THE IDENTITY

        headers = self.scope.get("headers", [])
        identity_header = next((val for key, val in headers if key.decode("utf-8") == "x-rh-identity"), {})
        decoded_identity_header = b64decode(identity_header)
        json_identity_header = json.loads(decoded_identity_header)
        self.account_number = json_identity_header.get("identity", {})["account_number"]
        self.channel_group_name = RbacConsumer.channel_group_name(self.account_number)
        await self.channel_layer.group_add(self.channel_group_name, self.channel_name)
        await self.accept()

        # SEND MOCK CONNECTION CONFIRMATION
        # await self.send(text_data=json.dumps({"message": connection_message}))
        # SEND MOCK CONNECTION CONFIRMATION

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.channel_group_name, self.channel_name)

    async def receive(self, text_data):
        pass

    async def tam_update(self, event):
        message = event["message"]
        await self.send(text_data=json.dumps({"message": message}))
