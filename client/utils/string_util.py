import base64


def string_to_base64(s_bytes):
    base64_bytes = base64.b64encode(s_bytes)
    base64_string = base64_bytes.decode('utf-8')
    return base64_string


def base64_to_string(base64_bytes):
    try:
        original_bytes = base64.b64decode(base64_bytes)
        return original_bytes
    except UnicodeDecodeError as e:
        print(f"Error decoding base64 bytes: {e}")
        return None
