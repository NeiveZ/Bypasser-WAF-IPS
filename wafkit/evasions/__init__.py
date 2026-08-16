"""Plugins de evasao — importar este pacote registra todas as tecnicas."""

from wafkit.evasions import registry  # noqa: F401
from wafkit.evasions import encoding  # noqa: F401
from wafkit.evasions import case  # noqa: F401
from wafkit.evasions import sql_comments  # noqa: F401
from wafkit.evasions import whitespace  # noqa: F401
from wafkit.evasions import charset  # noqa: F401
from wafkit.evasions import hpp  # noqa: F401
from wafkit.evasions import transport  # noqa: F401