import hashlib
import hmac
import random
import networkx as nx
import os
import numpy as np
from PIL import Image
import cv2
from tqdm import tqdm
import tempfile

def generate_graph(seed: int) -> nx.Graph:
    random.seed(seed)
    graph = nx.Graph()
    ascii_range = range(256)
    graph.add_nodes_from(ascii_range)
    for i in ascii_range:
        for j in ascii_range:
            if random.random() < 0.05:
                graph.add_edge(i, j)
    return graph

def randomize_graph(graph: nx.Graph, seed: int) -> nx.Graph:
    random.seed(seed)
    nodes = list(graph.nodes())
    random.shuffle(nodes)
    randomized_graph = nx.Graph()
    randomized_graph.add_nodes_from(nodes)
    randomized_graph.add_edges_from((nodes[i], nodes[j]) for i, j in graph.edges())
    return randomized_graph

def derive_key(key: str, salt: bytes = None) -> (int, bytes):
    if salt is None:
        salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac('sha256', key.encode(), salt, 50000)
    return int.from_bytes(derived_key, byteorder='big'), salt

def compute_param(pixel: int, derived_key: int, salt: int) -> int:
    return (pixel ^ derived_key ^ salt) % 256

def xor_encrypt(data: bytes, key: int) -> bytes:
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, byteorder='big')
    return bytes(d ^ key_bytes[i % len(key_bytes)] for i, d in enumerate(data))

def add_authentication(data: bytes, auth_key: bytes) -> bytes:
    hmac_digest = hmac.new(auth_key, data, hashlib.sha256).digest()
    return data + hmac_digest

def encrypt_frame(frame: np.ndarray, derived_key: int, coloring: dict) -> tuple:
    encrypted_visualization = np.random.randint(0, 256, frame.shape, dtype=np.uint8)
    encrypted_data = []
    
    for channel in range(frame.shape[2]):
        channel_data = []
        for i in range(frame.shape[0]):
            row_data = []
            for j in range(frame.shape[1]):
                pixel = frame[i, j, channel]
                color = coloring[pixel]
                salt_value = random.randint(0, 255)
                param = compute_param(pixel, derived_key, salt_value)
                row_data.append(f"{color}-{param}-{salt_value}")
            channel_data.extend(row_data)
        encrypted_data.extend(channel_data)
    
    return encrypted_data, encrypted_visualization

def decrypt_frame(encrypted_data: list, shape: tuple, derived_key: int, coloring: dict) -> np.ndarray:
    decrypted_array = np.zeros(shape, dtype=np.uint8)
    pixels_per_channel = shape[0] * shape[1]
    
    for channel in range(shape[2]):
        channel_start = channel * pixels_per_channel
        for i in range(shape[0]):
            for j in range(shape[1]):
                idx = channel_start + i * shape[1] + j
                color, param, salt_value = map(int, encrypted_data[idx].split('-'))
                
                for pixel, pixel_color in coloring.items():
                    if pixel_color == color and compute_param(pixel, derived_key, salt_value) == param:
                        decrypted_array[i, j, channel] = pixel
                        break
    
    return decrypted_array

def encrypt_video(video_path: str, key: str, output_path: str) -> None:
    # Open video file
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError("Could not open video file")
    
    # Get video properties
    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = int(cap.get(cv2.CAP_PROP_FPS))
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    
    # Prepare encryption components
    derived_key, salt = derive_key(key)
    graph = generate_graph(derived_key)
    randomized_graph = randomize_graph(graph, derived_key)
    coloring = nx.coloring.greedy_color(randomized_graph, strategy="random_sequential")
    
    # Create temporary file for encrypted data
    temp_data_file = tempfile.NamedTemporaryFile(delete=False, suffix='.enc')
    
    # Prepare video writers
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    encrypted_video = cv2.VideoWriter(output_path, fourcc, fps, (frame_width, frame_height))
    
    print("Encrypting video...")
    frame_data = []
    
    # Process each frame
    with tqdm(total=total_frames) as pbar:
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break
                
            # Encrypt frame
            encrypted_frame_data, encrypted_visual = encrypt_frame(frame, derived_key, coloring)
            frame_data.extend(encrypted_frame_data)
            
            # Write encrypted visualization
            encrypted_video.write(encrypted_visual)
            pbar.update(1)
    
    # Save encrypted data
    cipher_str = '|'.join(frame_data)
    encrypted_cipher = xor_encrypt(cipher_str.encode('utf-8'), derived_key)
    auth_key = hashlib.sha256(f"{derived_key}".encode()).digest()
    final_cipher = add_authentication(encrypted_cipher, auth_key)
    
    # Write metadata and encrypted data
    with open(temp_data_file.name, 'wb') as f:
        f.write(salt)  # Write salt first
        # Write video properties
        f.write(frame_width.to_bytes(4, byteorder='big'))
        f.write(frame_height.to_bytes(4, byteorder='big'))
        f.write(fps.to_bytes(4, byteorder='big'))
        f.write(total_frames.to_bytes(4, byteorder='big'))
        f.write(final_cipher)
    
    # Cleanup
    cap.release()
    encrypted_video.release()
    print(f"\nEncryption completed. Data saved to {temp_data_file.name}")
    return temp_data_file.name

def decrypt_video(encrypted_data_path: str, key: str, output_path: str) -> None:
    # Read encrypted data and metadata
    with open(encrypted_data_path, 'rb') as f:
        salt = f.read(16)
        frame_width = int.from_bytes(f.read(4), byteorder='big')
        frame_height = int.from_bytes(f.read(4), byteorder='big')
        fps = int.from_bytes(f.read(4), byteorder='big')
        total_frames = int.from_bytes(f.read(4), byteorder='big')
        encrypted_data = f.read()
    
    # Derive key and prepare decryption
    derived_key, _ = derive_key(key, salt)
    auth_key = hashlib.sha256(f"{derived_key}".encode()).digest()
    
    # Verify and decrypt data
    decrypted_data = verify_authentication(encrypted_data, auth_key)
    decrypted_str = xor_encrypt(decrypted_data, derived_key).decode('utf-8')
    frame_data = decrypted_str.split('|')
    
    # Prepare graph and coloring
    graph = generate_graph(derived_key)
    randomized_graph = randomize_graph(graph, derived_key)
    coloring = nx.coloring.greedy_color(randomized_graph, strategy="random_sequential")
    
    # Setup video writer
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(output_path, fourcc, fps, (frame_width, frame_height))
    
    # Calculate frames data size
    frame_size = frame_width * frame_height * 3  # 3 channels
    
    print("Decrypting video...")
    # Process each frame
    with tqdm(total=total_frames) as pbar:
        for frame_idx in range(total_frames):
            frame_data_slice = frame_data[frame_idx * frame_size:(frame_idx + 1) * frame_size]
            if not frame_data_slice:
                break
                
            # Decrypt frame
            frame = decrypt_frame(frame_data_slice, (frame_height, frame_width, 3), 
                                derived_key, coloring)
            
            # Write frame
            out.write(frame)
            pbar.update(1)
    
    out.release()
    print(f"\nDecryption completed. Video saved to {output_path}")

def verify_authentication(data: bytes, auth_key: bytes) -> bytes:
    received_data, received_hmac = data[:-32], data[-32:]
    expected_hmac = hmac.new(auth_key, received_data, hashlib.sha256).digest()
    if not hmac.compare_digest(received_hmac, expected_hmac):
        raise ValueError("Authentication failed.")
    return received_data

def main():
    video_path = 'input_video.mp4'
    key = "VideoEncryption"
    
    try:
        print("Starting video encryption...")
        encrypted_data_path = encrypt_video(video_path, key, 'encrypted_video.mp4')
        
        print("\nStarting video decryption...")
        decrypt_video(encrypted_data_path, key, 'decrypted_video.mp4')
        
        print("\nProcess completed successfully!")
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()