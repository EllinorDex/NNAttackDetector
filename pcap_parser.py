from scapy.all import *
from scapy.layers.all import *
import os
import socket
import csv
import subprocess
import re
import numpy as np
from scapy.layers.http import HTTPRequest, HTTPResponse

def split_pcap(traffic_type = 'normal'):
    raw_pcap_dir = 'code\pcap_'+ traffic_type + '\\'
    raw_pcap_files = os.listdir(raw_pcap_dir)
    sessions_pcap_dir = 'code\sessions_pcap_' + traffic_type + '\\'

    for raw_pcap_file in raw_pcap_files:
        proc = subprocess.Popen('code\SplitCap.exe -r ' + raw_pcap_dir + raw_pcap_file + ' -o ' + sessions_pcap_dir, shell=True, stdout=subprocess.PIPE)
        proc.wait()


def get_params_from_http(packet, session_statistic):
    if packet.haslayer(HTTPRequest):
        session_statistic['http_method'] = packet[HTTPRequest].Method.decode() if packet[HTTPRequest].Method else session_statistic['http_method']
        session_statistic['http_version'] = packet[HTTPRequest].Http_Version.decode() if packet[HTTPRequest].Http_Version else session_statistic['http_version']
        session_statistic['http_accept'] = packet[HTTPRequest].Accept.decode() if packet[HTTPRequest].Accept else session_statistic['http_accept']
        session_statistic['http_connection'] = packet[HTTPRequest].Connection.decode() if packet[HTTPRequest].Connection else session_statistic['http_connection']
        session_statistic['http_user_agent'] = packet[HTTPRequest].User_Agent.decode() if packet[HTTPRequest].User_Agent else session_statistic['http_user_agent']

    if packet.haslayer(HTTPResponse):
        session_statistic['http_version'] = packet[HTTPResponse].Http_Version.decode() if packet[HTTPResponse].Http_Version else session_statistic['http_version']
        session_statistic['http_status_code'] = packet[HTTPResponse].Status_Code.decode() if packet[HTTPResponse].Status_Code else session_statistic['http_status_code']
        session_statistic['http_connection'] = packet[HTTPResponse].Connection.decode() if packet[HTTPResponse].Connection else session_statistic['http_connection']
        session_statistic['http_content_length'] = packet[HTTPResponse].Content_Length.decode() if packet[HTTPResponse].Content_Length else session_statistic['http_content_length']
        session_statistic['http_content_type'] = packet[HTTPResponse].Content_Type.decode() if packet[HTTPResponse].Content_Type else session_statistic['http_content_type']
        session_statistic['http_server'] = packet[HTTPResponse].Server.decode() if packet[HTTPResponse].Server else session_statistic['http_server']



def get_correct_session_name(raw_session_name):
    str1 = re.split('\.', raw_session_name)[0]
    str2 = re.split('_', str1)
    ip1 = '.'.join(re.split('-', str2[0]))
    ip2 = '.'.join(re.split('-', str2[2]))
    correct_session_name = '__'.join([ip1,str2[1],ip2,str2[3]])
    return correct_session_name

def get_params(traffic_type = 'normal', protocol_pcap = 'http'):
    sessions_pcap_dir = 'code\sessions_pcap_' + traffic_type + '\\'

    #Собираемые параметры
    ses_stat = {
        'pcap_name': 'none',
        'session_identifier': 'none',
        'service': 'none',
        'protocol': 'none',
        'duration': 0,
        'total_count_bytes': 0,
        'total_count_packets': 0,
        'src_count_bytes': 0,
        'dst_count_bytes': 0,
        'src_count_packets': 0,
        'dst_count_packets': 0,
        'src_mean_packet_size': 0,
        'dst_mean_packet_size': 0,
        'src_min_packet_size': 0,
        'dst_min_packet_size': 0,
        'src_max_packet_size': 0,
        'dst_max_packet_size': 0,
        'src_std_packet_size': 0,
        'dst_std_packet_size': 0,
        'src_bytes_per_sec': 0,
        'dst_bytes_per_sec': 0,
        'min_time_delay': 0,
        'max_time_delay': 0,
        'mean_time_delay': 0,
        'std_time_delay': 0,
        'src_port': 'none',
        'dst_port': 'none',
        'flags': 'none',
        'http_method': 'none',
        'http_version': 'none',
        'http_accept': 'none',
        'http_connection': 'none',
        'http_user_agent': 'none',
        'http_version': 'none',
        'http_status_code': 'none',
        'http_connection': 'none',
        'http_content_length': 'none',
        'http_content_type': 'none',
        'http_server': 'none',
        }
    
    #Получение списка pcap с записанными сессиями
    pcap_files = os.listdir(sessions_pcap_dir)
    if 'log_file.csv' in pcap_files:
        pcap_files.remove('log_file.csv')

    #Выходной файл с записанными метриками сессий
    log_file =  open(sessions_pcap_dir + '\log_file.csv', 'w', newline="")
    writer = csv.DictWriter(log_file, fieldnames = ses_stat.keys())
    writer.writeheader()

    t = 0
    reg1 = re.compile(r'\.[TCUD]{2}P_')
    for pcap_file in pcap_files:
        names = re.split(reg1, pcap_file)
        ses_stat['pcap_name'] = names[0]
        ses_stat['session_identifier'] = get_correct_session_name(names[1])

        t+=1
        print('~~~',pcap_file,'~~~')
        #Открытие pcap файла
        pcap =  rdpcap(sessions_pcap_dir + pcap_file)
        session_statistic = ses_stat.copy()

        protocol = re.search(r"(TCP)", pcap_file)
        session_statistic['protocol'] = 'TCP' if protocol  else 'UDP'

        #Определение port источника и цели
        session_statistic['src_port'] = pcap[0][2].sport
        src_ip = pcap[0][1].src
        session_statistic['dst_port'] = pcap[0][2].dport
        dst_ip = pcap[0][1].dst

        flags = 0

        try:
            service = socket.getservbyport(pcap[0][2].dport)
            session_statistic['service'] = service
        except:
            try:
                service = socket.getservbyport(pcap[0][2].sport)
                session_statistic['service'] = service
            except:
                pass

        #Расмотрен каждый пакет сессии
        packet_times = [pcap[0].time]
        time_delays = []
        total_packet_sizes = []
        src_packet_sizes = []
        dst_packet_sizes = []
        for packet in pcap:

            if session_statistic['service']:
                get_params_from_http(packet, session_statistic)

            #Заполнение полей
            session_statistic['duration'] = packet.time - pcap[0].time
            time_delays.append(abs(packet.time - packet_times[-1]))
            packet_times.append(packet.time)
            
            total_packet_sizes.append(len(packet))
            session_statistic['total_count_packets'] += 1

            if packet[1].src == src_ip:
                session_statistic['src_count_packets'] += 1
                src_packet_sizes.append(len(packet))

            elif packet[1].src == dst_ip:
                session_statistic['dst_count_packets'] += 1
                dst_packet_sizes.append(len(packet))

            #Заполнение флагов при TCP сессии
            if session_statistic['protocol'] == 'TCP':
                flags = packet[TCP].flags | flags

            session_statistic['flags'] = flags if session_statistic['protocol'] == 'TCP' else ''
            #---------------------------------------------------

        time_delays.pop(0)
        if len(time_delays) != 0:
            session_statistic['min_time_delay'] = np.min(time_delays)
            session_statistic['max_time_delay'] = np.max(time_delays)
            session_statistic['mean_time_delay'] = np.mean(time_delays)
            session_statistic['std_time_delay'] = np.std(time_delays)

        if len(src_packet_sizes) != 0:
            session_statistic['src_mean_packet_size'] = np.mean(src_packet_sizes)
            session_statistic['src_min_packet_size'] = np.min(src_packet_sizes)
            session_statistic['src_max_packet_size'] = np.max(src_packet_sizes)
            session_statistic['src_std_packet_size'] = np.std(src_packet_sizes)
            session_statistic['src_count_bytes'] = np.sum(src_packet_sizes)
            sum_src_packet_sizes = np.sum(src_packet_sizes)
        else:
            sum_src_packet_sizes = 0
        
        if len(dst_packet_sizes) != 0:
            session_statistic['dst_mean_packet_size'] = np.mean(dst_packet_sizes)
            session_statistic['dst_min_packet_size'] = np.min(dst_packet_sizes)
            session_statistic['dst_max_packet_size'] = np.max(dst_packet_sizes)
            session_statistic['dst_std_packet_size'] = np.std(dst_packet_sizes)
            session_statistic['dst_count_bytes'] = np.sum(dst_packet_sizes)
            sum_dst_packet_sizes = np.sum(dst_packet_sizes)
        else:
            sum_dst_packet_sizes = 0
        
        session_statistic['total_count_bytes'] = session_statistic['dst_count_bytes'] + session_statistic['src_count_bytes']
        session_statistic['src_bytes_per_sec'] = (sum_src_packet_sizes /
        session_statistic['duration']) if session_statistic['duration'] != 0 else session_statistic['src_count_bytes']
        session_statistic['dst_bytes_per_sec'] = (sum_dst_packet_sizes /
        session_statistic['duration']) if session_statistic['duration'] != 0 else session_statistic['dst_count_bytes']

        #Добавление строчки в конец файла
        writer.writerow(session_statistic)
    
    log_file.close()


#Сам вызов функции
if __name__ == '__main__':
    labels = ['normal', 'attack_sqlinj', 'attack_brokauth', 'attack_zeus']

    for label in labels:
        #split_pcap(label)
        get_params(label)


