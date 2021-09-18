import pandas as pd

def get_ready_data(paths_to_log_traffic, names):
    path_to_log_normal = paths_to_log_traffic[0]
    paths_to_log_attacks = paths_to_log_traffic[1:]

    df_n = pd.read_csv(path_to_log_normal)
    for i in range(len(paths_to_log_attacks)):
        df_n.insert(df_n.shape[1], 'attack_' + names[i], 0)

    dfs_a = []
    for path_to_log_attacks in paths_to_log_attacks:
        dfs_a.append(pd.read_csv(path_to_log_attacks))
    
    for i in range(len(paths_to_log_attacks)):
        for j in range(len(paths_to_log_attacks)):
            if i == j:
                dfs_a[i].insert(dfs_a[i].shape[1], 'attack_' + names[j], 1)
            else:
                dfs_a[i].insert(dfs_a[i].shape[1], 'attack_' + names[j], 0)

    labels = df_n.columns.to_list()

    categorical = [
        'protocol',
        'src_port',
        'dst_port',
        'flags',
        'http_method',
        'http_version',
        'http_accept',
        'http_connection',
        'http_user_agent',
        'http_version',
        'http_status_code',
        'http_connection',
        'http_content_length',
        'http_content_type',
        'http_server',
    ]
    for categoria in categorical:
        df_n[categoria] = df_n[categoria].astype('category')
        df_n[categoria] = df_n[categoria].cat.codes

        for df_a in dfs_a:
            df_a[categoria] = df_a[categoria].astype('category')
            df_a[categoria] = df_a[categoria].cat.codes
    
    labels = labels[3:]

    df = pd.concat(dfs_a + [df_n])
    normalized_df = (df[labels]-df[labels].min()) / (df[labels].max()-df[labels].min())
    normalized_df = normalized_df.fillna(df.mean())
    
    normalized_df.insert(0, 'service', df.service)
    normalized_df.insert(0, 'session_identifier', df.session_identifier)
    normalized_df.insert(0, 'pcap_name', df.pcap_name)
    
    print('Записей обработано:',normalized_df.shape[0])
    print('Столбцов содержится:',normalized_df.shape[1])

    return normalized_df

if __name__ == '__main__':
    names = ['sqlinj', 'brokauth', 'zeus']

    df = get_ready_data(['code/sessions_pcap_normal/log_file.csv'] +
    ['code/sessions_pcap_attack_' + name + '/log_file.csv' for name in names], names)
    df = df.sample(frac=1, random_state=113)

    df.to_csv('code/normalized_df_attack.csv', columns = df.columns.to_list(), index=False)