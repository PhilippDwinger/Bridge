def split_text(text: str, max_bytes: int) -> list[str]:
    """Splits text into chunks of at most max_bytes UTF-8 bytes without cutting a character in half.

    Joining all chunks in order gives the original text again.
    """
    if max_bytes < 4:
        raise ValueError("max_bytes must be at least 4 (longest UTF-8 character)")
    data = text.encode("utf-8")
    chunks = []
    start = 0
    while start < len(data):
        end = min(start + max_bytes, len(data))
        # Step back while we are inside a multi byte character (continuation bytes look like 10xxxxxx)
        while end < len(data) and (data[end] & 0xC0) == 0x80:
            end -= 1
        chunks.append(data[start:end].decode("utf-8"))
        start = end
    return chunks
