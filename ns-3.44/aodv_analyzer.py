import pyshark
import matplotlib.pyplot as plt
import pandas as pd
from glob import glob
import os

def analyze_aodv_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter='aodv')
    
    stats = {
        'total_packets': 0,
        'total_bytes': 0,
        'rreq_packets': 0,
        'rrep_packets': 0,
        'rerr_packets': 0,
        'other_packets': 0
    }
    
    for pkt in cap:
        stats['total_packets'] += 1
        stats['total_bytes'] += int(pkt.length)
        
        try:
            aodv_type = int(pkt.aodv.type)
            if aodv_type == 1:
                stats['rreq_packets'] += 1
            elif aodv_type == 2:
                stats['rrep_packets'] += 1
            elif aodv_type == 3:
                stats['rerr_packets'] += 1
            else:
                stats['other_packets'] += 1
        except AttributeError:
            stats['other_packets'] += 1
    
    cap.close()
    return stats

def analyze_all_pcaps(pcap_files):
    all_stats = []
    
    for file in pcap_files:
        print(f"Processando {os.path.basename(file)}...")
        stats = analyze_aodv_pcap(file)
        stats['filename'] = os.path.basename(file)
        stats['node'] = os.path.basename(file).split('-')[-1].split('.')[0]
        all_stats.append(stats)
    
    return pd.DataFrame(all_stats)

def generate_plots(df):
    plt.style.use('ggplot')
    
    # Gráfico de Distribuição dos tipos de pacotes
    type_counts = df[['rreq_packets', 'rrep_packets', 'rerr_packets']].sum()
    plt.figure(figsize=(8, 6))
    type_counts.plot.pie(autopct='%1.1f%%', 
                        labels=['RREQ', 'RREP', 'RERR'],
                        colors=['#ff9999','#66b3ff','#99ff99'])
    plt.title('Distribuição dos Tipos de Pacotes AODV')
    plt.ylabel('')
    plt.savefig('aodv_packet_types_distribution.png')


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
        <title>Relatório de Análise AODV</title>
        {style}
    </head>
    <body>
        <h1>Relatório de Análise de Pacotes AODV</h1>
        
        <h2>Resumo Geral</h2>
        <p>Total de pacotes AODV: {df['total_packets'].sum()}</p>
        <p>Total de bytes AODV: {df['total_bytes'].sum()} bytes</p>
        
        <h2>Estatísticas por Nó</h2>
        {df.to_html(index=False)}
        
        <h2>Gráfico</h2>
        
        <h3>Distribuição dos Tipos de Pacotes</h3>
        <img src="aodv_packet_types_distribution.png" alt="Distribuição de Tipos">
        
    </body>
    </html>
    """
    
    with open('aodv_analysis_report.html', 'w') as f:
        f.write(html_content)

def main():
    # Encontra todos os arquivos PCAP no diretório atual
    pcap_files = glob('aodv-control-*.pcap')
    
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
    print(f"Total de pacotes AODV: {df['total_packets'].sum()}")
    print(f"Total de bytes AODV: {df['total_bytes'].sum()} bytes")
    print("\nDistribuição dos tipos de pacotes:")
    print(f"- RREQ: {df['rreq_packets'].sum()} pacotes")
    print(f"- RREP: {df['rrep_packets'].sum()} pacotes")
    print(f"- RERR: {df['rerr_packets'].sum()} pacotes")
    print(f"- Outros: {df['other_packets'].sum()} pacotes")
    
    print("\nAnálise concluída. Relatório gerado em 'aodv_analysis_report.html'")

if __name__ == "__main__":
    main()
