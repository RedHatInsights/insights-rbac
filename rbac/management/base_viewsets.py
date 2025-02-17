# Copyright 2024 Red Hat, Inc.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Base viewset for v2 APIs."""
from django.apps import apps
from rest_framework import mixins, viewsets
from rest_framework.settings import api_settings

from api.common.renderers import ProblemJSONRenderer


class BaseV2ViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    """Base views to be inhertied for v2 API views."""

    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES + [ProblemJSONRenderer]

    def get_queryset(self):
        """Dynamic override of the default queryset for v2 APIs."""
        model = apps.get_model("management", self.basename)
        return model.objects.filter(tenant=self.request.tenant)
