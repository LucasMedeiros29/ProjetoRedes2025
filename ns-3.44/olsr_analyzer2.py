import pyshark
import matplotlib.pyplot as plt
import pandas as pd
from glob import glob
import os
import re

def analyze_olsr_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='olsr')
    
    stats = {
        'total_packets': 0,
        'total_bytes': 0,
        'hello_packets': 0,
        'tc_packets': 0,
        'mid_packets': 0,
        'other_packets': 0
    }
    
    patterns = {
        'hello': re.compile(r'olsr\.message\.hello|hello|HELLO', re.IGNORECASE),
        'tc': re.compile(r'olsr\.message\.tc|topology|TC', re.IGNORECASE),
        'mid': re.compile(r'olsr\.message\.mid|interface|MID', re.IGNORECASE)
    }
    
    for pkt in cap:
        stats['total_packets'] += 1
        stats['total_bytes'] += int(pkt.length)
        pkt_data = str(pkt).lower()
        
        if patterns['hello'].search(pkt_data):
            stats['hello_packets'] += 1
        elif patterns['tc'].search(pkt_data):
            stats['tc_packets'] += 1
        elif patterns['mid'].search(pkt_data):
            stats['mid_packets'] += 1
        else:
            stats['other_packets'] += 1
    
    cap.close()
    return stats

def analyze_all_pcaps(pcap_files):
    all_stats = []
    
    for file in pcap_files:
        print(f"Processando {os.path.basename(file)}...")
        stats = analyze_olsr_pcap(file)
        stats['filename'] = os.path.basename(file)
        stats['node'] = os.path.basename(file).split('-')[-1].split('.')[0]
        all_stats.append(stats)
    
    return pd.DataFrame(all_stats)

def generate_plots(df):
    plt.style.use('ggplot')
    
    # Gráfico de Distribuição dos tipos de pacotes
    type_counts = df[['hello_packets', 'tc_packets', 'mid_packets']].sum()
    plt.figure(figsize=(8, 6))
    type_counts.plot.pie(autopct='%1.1f%%', 
                        labels=['HELLO', 'TC', 'MID'],
                        colors=['#ff9999','#66b3ff','#99ff99'])
    plt.title('Distribuição dos Tipos de Pacotes OLSR')
    plt.ylabel('')
    plt.savefig('olsr_packet_types_distribution.png')
    

def generate_report(df):
    """relatório em HTML"""
    style = """
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        img { max-width: 100%; height: auto; margin-bottom: 20px; }
    </style>
    """
    
    # Cria o HTML
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Relatório de Análise OLSR</title>
        {style}
    </head>
    <body>
        <h1>Relatório de Análise de Pacotes OLSR</h1>
        
        <h2>Resumo Geral</h2>
        <p>Total de pacotes OLSR: {df['total_packets'].sum()}</p>
        <p>Total de bytes OLSR: {df['total_bytes'].sum()} bytes</p>
        
        <h2>Estatísticas por Nó</h2>
        {df.to_html(index=False)}
        
        <h2>Gráfico</h2>
        
        <h3>Distribuição dos Tipos de Pacotes</h3>
        <img src="olsr_packet_types_distribution.png" alt="Distribuição de Tipos">
        
    </body>
    </html>
    """
    
    with open('olsr_analysis_report.html', 'w') as f:
        f.write(html_content)

def main():
    # Encontra todos os arquivos PCAP no diretório atual
    pcap_files = glob('olsr-control-*.pcap')
    
    if not pcap_files:
        print("Nenhum arquivo PCAP encontrado. Certifique-se de que os arquivos estão no diretório atual.")
        return
    
    print(f"Encontrados {len(pcap_files)} arquivos PCAP para análise...")
    
    # Analisa todos os arquivos
    df = analyze_all_pcaps(pcap_files)
    
    # Gera o gráfico
    generate_plots(df)
    
    # Gera o HTML
    generate_report(df)
    
    # resumo no console
    print("\n=== RESUMO DA ANÁLISE ===")
    print(f"Total de pacotes OLSR: {df['total_packets'].sum()}")
    print(f"Total de bytes OLSR: {df['total_bytes'].sum()} bytes")
    print("\nDistribuição dos tipos de pacotes:")
    print(f"- HELLO: {df['hello_packets'].sum()} pacotes")
    print(f"- TC:    {df['tc_packets'].sum()} pacotes")
    print(f"- MID:   {df['mid_packets'].sum()} pacotes")
    print(f"- Outros: {df['other_packets'].sum()} pacotes")
    
    print("\nAnálise concluída. Relatório gerado em 'olsr_analysis_report.html'")

if __name__ == "__main__":
    main()
