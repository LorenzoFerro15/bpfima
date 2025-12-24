import matplotlib.pyplot as plt
import sys
import numpy as np

def parse_and_plot_heatmap(filename):
    data = []
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                if ',' in line:
                    parts = line.strip().split(',')
                    if len(parts) == 4:
                        size = parts[0]
                        # Convert Overhead to ms
                        overhead = int(parts[3]) / 1_000_000.0
                        data.append({'Size': size, 'Overhead': overhead})
    except FileNotFoundError:
        return

    if not data:
        return

    # Extract unique sizes to preserve order
    sizes = []
    seen = set()
    for entry in data:
        if entry['Size'] not in seen:
            sizes.append(entry['Size'])
            seen.add(entry['Size'])
    
    size_map = {size: i for i, size in enumerate(sizes)}
    
    x = []
    y = []
    
    for entry in data:
        x.append(size_map[entry['Size']])
        y.append(entry['Overhead'])

    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Scatter plot: color mapped to Y value (Overhead)
    # cmap='RdYlGn_r' gives Green (low) to Red (high)
    sc = ax.scatter(x, y, c=y, cmap='RdYlGn_r', alpha=0.7, s=150, edgecolors='black', linewidth=1)
    
    ax.set_xticks(range(len(sizes)))
    ax.set_xticklabels(sizes)
    ax.set_title('BPF Overhead Distribution by Binary Size')
    ax.set_ylabel('Overhead (ms)')
    ax.set_xlabel('Binary Size')
    ax.grid(True, linestyle='--', alpha=0.3)
    
    # Add colorbar to show scale
    cbar = plt.colorbar(sc, ax=ax)
    cbar.set_label('Overhead (ms)')
    
    plt.tight_layout()
    
    output_file = 'exec_overhead_heatmap.pdf'
    plt.savefig(output_file)
    plt.close(fig)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_and_plot_heatmap(sys.argv[1])
