# compression.py
from collections import Counter, deque
from io import BytesIO


class HuffmanNode:
    def __init__(self, char, freq):
        self.char = char
        self.freq = freq
        self.left = None
        self.right = None

    def __lt__(self, other):
        return self.freq < other.freq


def build_huffman_tree(frequency):
    nodes = deque(sorted([HuffmanNode(char, freq) for char, freq in frequency.items()], key=lambda x: x.freq))

    while len(nodes) > 1:
        left = nodes.popleft()
        right = nodes.popleft()
        merged = HuffmanNode(None, left.freq + right.freq)
        merged.left = left
        merged.right = right
        nodes.appendleft(merged)
        nodes = deque(sorted(nodes, key=lambda x: x.freq))  # Sort nodes after adding merged node

    return nodes[0] if nodes else None


def generate_huffman_codes(node, prefix="", code_map={}):
    if node is not None:
        if node.char is not None:
            code_map[node.char] = prefix
        generate_huffman_codes(node.left, prefix + "0", code_map)
        generate_huffman_codes(node.right, prefix + "1", code_map)
    return code_map


def huffman_compress(data):
    frequency = Counter(data)
    huffman_tree = build_huffman_tree(frequency)
    huffman_codes = generate_huffman_codes(huffman_tree)
    compressed_data = "".join(huffman_codes[char] for char in data)
    return compressed_data, huffman_tree


def compress_and_encode(file, filename):
    """Reads file content, applies Huffman compression, and encodes as binary data."""
    data = file.read()  # Read file content as bytes
    compressed_data, huffman_tree = huffman_compress(data)
    compressed_bytes = int(compressed_data, 2).to_bytes((len(compressed_data) + 7) // 8, byteorder='big')

    # Create BytesIO object and manually assign a 'name' attribute
    compressed_file = BytesIO(compressed_bytes)
    compressed_file.name = filename  # Set the filename manually

    return compressed_file
