import matplotlib.pyplot as plt
import matplotlib.animation as animation
import numpy as np

# Simplified Python version of transposition cipher for visualization
class KeyedPRNG:
    def __init__(self, key16):
        a = int.from_bytes(key16[:8], 'big')
        b = int.from_bytes(key16[8:], 'big')
        self.s = a ^ ((b << 1) | (b >> 63)) ^ 0x9E3779B97F4A7C15
        if self.s == 0:
            self.s = 0xDEADBEEFC0FFEE

    def next64(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = self.s
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9 & 0xFFFFFFFFFFFFFFFF
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB & 0xFFFFFFFFFFFFFFFF
        z ^= z >> 31
        return z & 0xFFFFFFFFFFFFFFFF

    def next32(self):
        return self.next64() & 0xFFFFFFFF

def apply_transposition(data, rows, cols, key16):
    prng = KeyedPRNG(key16)
    arr = np.array(data, dtype=np.uint8).reshape(rows, cols)
    
    # simple shuffle rows for visualization
    row_indices = np.arange(rows)
    for i in range(rows-1, 0, -1):
        j = prng.next32() % (i+1)
        row_indices[i], row_indices[j] = row_indices[j], row_indices[i]

    shuffled = arr[row_indices, :]
    return shuffled, row_indices

# Prepare data
rows, cols = 8, 8
original_data = np.arange(rows*cols, dtype=np.uint8)
key16 = bytes(range(16))

# Run transposition
shuffled, row_indices = apply_transposition(original_data, rows, cols, key16)

# Animation setup
fig, axes = plt.subplots(1, 2, figsize=(8, 4))
ax_orig, ax_perm = axes

# Left: original grid
ax_orig.set_title("Original Data Grid")
orig_img = ax_orig.imshow(original_data.reshape(rows, cols), cmap='viridis', vmin=0, vmax=255)

# Right: permuted grid
ax_perm.set_title("Permuted Data Grid")
perm_img = ax_perm.imshow(np.zeros((rows, cols), dtype=np.uint8), cmap='viridis', vmin=0, vmax=255)

def init():
    perm_img.set_data(np.zeros((rows, cols), dtype=np.uint8))
    return [perm_img]

def update(frame):
    permuted = original_data.reshape(rows, cols).copy()
    permuted = permuted[row_indices, :]
    # Simulate progressive reveal of permutation
    partial_perm = np.copy(original_data.reshape(rows, cols))
    for r in range(frame+1):
        partial_perm[r, :] = permuted[r, :]
    perm_img.set_data(partial_perm)
    return [perm_img]

ani = animation.FuncAnimation(fig, update, frames=rows, init_func=init,
                               blit=True, interval=800, repeat=False)

plt.show()

