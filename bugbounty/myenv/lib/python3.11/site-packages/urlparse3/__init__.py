__doc__ = """
Urlparse3 is simple and powerful url parsing tool.
Url must conform RFC 3986. Scheme is required and must be followed be colon.
Example usage:

import urlparse3


url = "http://domain.com/path/?id=1&id=2#anchor"
parsed_url = urlparse3.parse_url(url)
print parsed_url.query["id"]  # ["1", "2"]
parsed_url.query["name"] = "alex"
# get url back to string representation
print parsed_url.geturl()  # "http://domain.com/path/?id=1&id=2&name=alex#anchor"
"""

from .urlparse3 import parse_url, ParsedUrl