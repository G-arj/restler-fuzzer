# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This grammar was created manually.
# There is no corresponding OpenAPI spec.

from __future__ import print_function
import json

from engine import primitives
from engine.core import requests
from engine.errors import ResponseParsingException
from engine import dependencies

req_collection = requests.RequestCollection([])

request = requests.Request([
    primitives.restler_static_string("PUT "),
    primitives.restler_static_string("/"),
    primitives.restler_custom_payload("result"),
    primitives.restler_static_string("/"),
    primitives.restler_fuzzable_number("1.1"),
    primitives.restler_static_string("/A/"),
    primitives.restler_fuzzable_string("fuzzstring"),
    primitives.restler_static_string("/B/"),
    primitives.restler_fuzzable_int("1"),
    primitives.restler_static_string("/C/"),
    primitives.restler_custom_payload("type"),
    primitives.restler_static_string(" HTTP/1.1\r\n"),
    primitives.restler_static_string("Accept: application/json\r\n"),
    primitives.restler_static_string("Host: restler.unit.test.server.com\r\n"),
    primitives.restler_static_string("Content-Type: application/json\r\n"),
    primitives.restler_refreshable_authentication_token("authentication_token_tag"),
    primitives.restler_static_string("\r\n"),

],
requestId="/A/{name}/B/{id}/C/{type}"
)
req_collection.add_request(request)

