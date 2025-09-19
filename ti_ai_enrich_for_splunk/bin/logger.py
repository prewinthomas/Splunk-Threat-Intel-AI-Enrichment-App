import logging
import os

def get_logger(name="ti_ai_enrich"):
    # Ensure log directory exists
    log_dir = os.path.join(os.path.dirname(__file__), "..", "var", "log")
    os.makedirs(log_dir, exist_ok=True)

    log_path = os.path.join(log_dir, "ti_ai_enrich.log")

    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.FileHandler(log_path)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
