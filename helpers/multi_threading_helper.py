import concurrent.futures
import os

from helpers.handlers import exception_handler
from helpers.logging_helper import get_logger
from helpers.logging_helper import log_frame_debug

logger = get_logger(__name__)


def run_parallel_with_generic_args(function, *args, **kwargs):
    return_value = []
    try:
        log_frame_debug(logger, f"Scheduling parallel threads for {function.__name__}")
        iterable = kwargs.pop("iterable", None) or []
        max_workers = kwargs.pop("max_workers", None) or min(32, (os.cpu_count() or 1) + 4)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for element in iterable:
                future = executor.submit(function, element, *args, **kwargs)
                futures.append(future)

        concurrent.futures.wait(futures)
        log_frame_debug(logger, f"All parallel threads for {function.__name__} completed")
        for future in futures:
            if future.result():
                result = future.result()
                result and return_value.extend(result)
    except Exception as e:
        exception_handler(e, args=dict(function=function))
    return return_value
