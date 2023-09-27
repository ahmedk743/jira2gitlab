import datetime
import sys
from inspect import currentframe
from inspect import getframeinfo as fi

from helpers.logging_helper import get_logger
from helpers.logging_helper import log_frame_error
from helpers.logging_helper import log_frame_warning
from helpers.logging_helper import oneline_exc_info

logger = get_logger(__name__)


def exception_handler(e, do_exit=False, args=None):
    if isinstance(e, KeyboardInterrupt):
        logger.warning(oneline_exc_info())
        return

    log_frame_error(logger, frame=fi(currentframe().f_back), args=args, ERROR=e)
    logger.exception(e)
    if do_exit:
        sys.exit(1)


def datetime_handler(input_date):
    if isinstance(input_date, datetime.datetime):
        return input_date.isoformat()
    if isinstance(input_date, bytes):
        log_frame_warning(logger, f'Converting a bytes type object into string, object: {input_date}')
        return input_date.decode("utf-8")
    raise TypeError(f"Unknown type, input: {input_date}, type: {type(input_date)}")
