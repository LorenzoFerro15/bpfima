import matplotlib.pyplot as plt
import sys
from collections import defaultdict
import numpy as np

def parse_and_plot_throughput(filename):
    # Data structure: data[type] = [(count, time_ns), ...]
    data = defaultdict(list)
    
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line: continue
            
            # Expected format: "Type: Exec | Count: 50 | Time: 123456789 ns"
            if "Type:" in line and "Count:" in line and "Time:" in line:
                parts = line.split('|')
                type_part = parts[0].split(':')[1].strip()
                count_part = int(parts[1].split(':')[1].strip())
                time_str = parts[2].split(':')[1].strip().split()[0]
                time_ns = int(time_str)
                
                # Convert to seconds or milliseconds for easier reading? 
                # Let's use milliseconds
                time_ms = time_ns / 1_000_000.0
                
                data[type_part].append((count_part, time_ms))
                
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return

    if not data:
        print("No throughput data found to plot.")
        return

    # Create the plot
    fig, ax = plt.subplots(figsize=(10, 6))
    
    colors = {'Exec': 'firebrick', 'Socket': 'royalblue'}
    markers = {'Exec': 'o', 'Socket': 's'}
    
    for test_type, points in data.items():
        # Sort by count
        points.sort(key=lambda x: x[0])
        
        counts = [p[0] for p in points]
        # Calculate Average Time per Operation in ms
        # p[1] is total time in ms, p[0] is count
        avg_times = [p[1] / p[0] for p in points]
        
        ax.plot(counts, avg_times, marker=markers.get(test_type, 'o'), 
                label=test_type, color=colors.get(test_type, 'black'), 
                linestyle='-', linewidth=2)
        
        # Annotate last point
        last_count = counts[-1]
        last_avg = avg_times[-1]
        ax.annotate(f'{last_avg:.4f}ms', xy=(last_count, last_avg), 
                    xytext=(5, 5), textcoords='offset points')

    ax.set_title('Throughput Analysis: Average Time per Operation')
    ax.set_xlabel('Number of Operations (Calls)')
    ax.set_ylabel('Average Time per Op (ms)')
    ax.set_ylim(bottom=0)
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.legend()
    
    output_file = 'throughput_analysis.pdf'
    plt.savefig(output_file)
    print(f"Throughput plot saved to {output_file}")
    plt.close(fig)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_and_plot_throughput(sys.argv[1])
    else:
        print("Usage: python3 plot_throughput.py <logfile>")
