from copy import deepcopy
from unittest.mock import Mock, patch, DEFAULT


def copy_call_args(mock):
    kafka_mock = Mock()

    def side_effect(*args, **kwargs):
        args = deepcopy(args)
        kwargs = deepcopy(kwargs)
        kafka_mock(*args, **kwargs)
        return DEFAULT

    mock.side_effect = side_effect
    return kafka_mock
