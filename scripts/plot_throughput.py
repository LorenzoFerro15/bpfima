import matplotlib.pyplot as plt
import sys
from collections import defaultdict

def parse_and_plot_throughput(filename):
    data = defaultdict(lambda: defaultdict(list))
    
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line: continue
            
            if "Type:" in line and "Phase:" in line and "Count:" in line and "Time:" in line:
                parts = line.split('|')
                type_part = parts[0].split(':')[1].strip()
                phase_part = parts[1].split(':')[1].strip()
                count_part = int(parts[2].split(':')[1].strip())
                time_str = parts[3].split(':')[1].strip().split()[0]
                time_ns = int(time_str)
                time_ms = time_ns / 1_000_000.0
                
                data[type_part][phase_part].append((count_part, time_ms))
                
    except FileNotFoundError:
        return

    if not data:
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    
    colors = {'Exec': 'firebrick', 'Socket': 'royalblue'}
    styles = {'Stable': '-', 'Warm': '-', 'Cold': '--', 'Baseline': ':'}
    
    for test_type, phases in data.items():
        base_color = colors.get(test_type, 'black')
        
        for phase, points in phases.items():
            points.sort(key=lambda x: x[0])
            counts = [p[0] for p in points]
            avg_times = [p[1] / p[0] for p in points]
            
            style = styles.get(phase, '-')
            
            # Simplified legend if it's the main stable run
            if phase == 'Stable':
                label_str = test_type
            else:
                label_str = f"{test_type} ({phase})"
            
            ax.plot(counts, avg_times, marker='o', 
                    label=label_str, color=base_color, 
                    linestyle=style, linewidth=2)
            
            if phase == 'Stable':
                last_count = counts[-1]
                last_avg = avg_times[-1]
                ax.annotate(f'{last_avg:.2f}ms', xy=(last_count, last_avg), 
                            xytext=(5, 5), textcoords='offset points', fontsize=8)

    ax.set_title('Throughput Analysis: Average Time per Operation')
    ax.set_xlabel('Number of Operations (Calls)')
    ax.set_ylabel('Average Time per Op (ms)')
    ax.set_ylim(bottom=0)
    ax.grid(True, linestyle='--', alpha=0.7)
    ax.legend()
    
    output_file = 'throughput_analysis.pdf'
    plt.savefig(output_file)
    plt.close(fig)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parse_and_plot_throughput(sys.argv[1])
