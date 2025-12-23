import matplotlib.pyplot as plt
import csv
import sys
import numpy as np

def plot_heatmap(filename):
    sizes = []
    overheads = []
    latencies_base = []
    latencies_bpf = []

    # Define the ordered sizes for the X-axis
    ordered_sizes = ["4K", "64K", "1M", "10M", "50M", "100M"]
    size_map = {s: i for i, s in enumerate(ordered_sizes)}

    x_vals = []
    y_vals = []
    c_vals = []

    try:
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if not row: continue
                # Expected format: Size, Baseline, BPF, Overhead_NS
                if len(row) < 4: continue
                
                s = row[0]
                if s in size_map:
                    x_vals.append(size_map[s])
                    overhead_ns = int(row[3])
                    overhead_ms = overhead_ns / 1_000_000.0
                    y_vals.append(overhead_ms)
                    c_vals.append(overhead_ms)
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
        return

    if not x_vals:
        print("No valid data found.")
        return

    # Setup Plot
    fig, ax = plt.subplots(figsize=(10, 6))

    # Create a colormap
    norm = plt.Normalize(min(c_vals), max(c_vals))
    cmap = plt.cm.RdYlGn_r 

    # Plot Dots (Scatter)
    # Using alpha to show overlap intensity
    sc = ax.scatter(x_vals, y_vals, c=c_vals, cmap=cmap, norm=norm, s=200, edgecolor='black', alpha=0.8, zorder=3)

    # Grid
    ax.grid(True, linestyle='--', alpha=0.7, zorder=0)

    # Labels and Titles
    ax.set_ylabel('Overhead (ms)')
    ax.set_xlabel('Executable Size')
    ax.set_title('BPF-IMA Overhead vs. File Size (Exec Latency)')
    
    # Set X-ticks to the ordered names
    ax.set_xticks(range(len(ordered_sizes)))
    ax.set_xticklabels(ordered_sizes)
    
    # Add Colorbar
    cbar = plt.colorbar(sc, ax=ax)
    cbar.set_label('Overhead (ms)')

    # No text annotations needed as per previous request

    plt.tight_layout()
    output_file = 'exec_overhead_heatmap.pdf'
    plt.savefig(output_file)
    print(f"Heatmap plot saved to {output_file}")
    plt.close(fig)

if __name__ == "__main__":
    file_path = "size_exec_latency.log"
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    plot_heatmap(file_path)
