"""
pdf.py builds PDFs by hand, no PDF library needed
"""

"Bytes either side of the dead zone, more than a viewer's biggest read (poppler 16KB, pypdf 128KB)"
GUARD = 256 * 1024

"Dead zone size, big so reading the whole file can't avoid it"
GAP = 4 * 1024 * 1024


def build_pdf(text: str, guard: int = 0, gap: int = 0) -> tuple[bytes, range]:
    """
    One page PDF showing `text`. With a gap it adds an unlinked stream of guard + gap + guard
    bytes that viewers never load.

    Returns the PDF and the byte range of the gap.
    """
    stream = f"BT /F1 24 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R",
        b" /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    out = b"%PDF-1.4\n"
    offsets: list[int] = []
    for num, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (num, body)

    zone = range(0)
    if gap:
        junk = bytes(guard + gap + guard)
        head = b"%d 0 obj\n<< /Length %d >>\nstream\n" % (len(objects) + 1, len(junk))
        offsets.append(len(out))
        start = len(out) + len(head) + guard
        zone = range(start, start + gap)
        out += head + junk + b"\nendstream\nendobj\n"

    # The xref table lists the byte offset of every object
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(offsets) + 1)
    out += b"".join(b"%010d 00000 n \n" % off for off in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(offsets) + 1,
        xref,
    )
    return out, zone


def minimal_pdf(text: str) -> bytes:
    "One page PDF showing `text`"
    return build_pdf(text)[0]


def dead_zone_pdf(text: str, guard: int = GUARD, gap: int = GAP) -> tuple[bytes, range]:
    """
    PDF with a big block that viewers never read. They read the head and tail, then follow
    the xref to objects reachable from the catalog, and nothing links to the stream holding
    the block.

    Returns the PDF and the byte range of the dead zone.
    """
    return build_pdf(text, guard, gap)
