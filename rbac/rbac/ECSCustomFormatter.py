#
# Copyright 2021 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

"""Custom ECS System formatter"""
import django_log_formatter_ecs
import json

ECS_VERSION = "1.6"


class ECSSystemFormatter(django_log_formatter_ecs.ECSSystemFormatter):
    def get_event(self):
        logger_event = self._get_event_base()
        logger_event.ecs(ECS_VERSION)

        return logger_event


class ECSRequestFormatter(django_log_formatter_ecs.ECSRequestFormatter):
    def get_event(self):
        logger_event = super().get_event()
        logger_event.ecs(ECS_VERSION)

        return logger_event


ECS_FORMATTERS = {
    "root": ECSSystemFormatter,
    "django.request": ECSRequestFormatter,
    "django.db.backends": ECSSystemFormatter,
}


class ECSFormatter(django_log_formatter_ecs.ECSFormatter):
    def format(self, record):
        if record.name in ECS_FORMATTERS:
            ecs_formatter = ECS_FORMATTERS[record.name]
        else:
            ecs_formatter = ECSSystemFormatter

        formatter = ecs_formatter(record=record)
        logger_event = formatter.get_event()

        logger_event.log(level=self._get_severity(record.levelname))

        log_dict = logger_event.get_log_dict()

        return json.dumps(log_dict)
