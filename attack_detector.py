from module_system import ModuleSystem

import pandas as pd
import numpy as np
pd.options.mode.chained_assignment = None


def network_traffic_classification():
    # Задание обнаруживаемых типов атак
    names_with_attack = ['attack_sqlinj', 'attack_brokauth', 'attack_zeus']
    names = ['sql_injection', 'broken_auth', 'zeus']
    number_of_attacks = len(names_with_attack)
    
    # Загрузка наборы данных для обучения и тестирования
    df = pd.read_csv('normalized_df_attack.csv')
    labels = df.columns.to_list()[3:-number_of_attacks]
    count_of_features = len(labels)

    # Создание системы и добавления обнаруживающих модулей
    ms = ModuleSystem()
    for name in names:
        ms.add_detection_module(name, 'http', count_of_features)

    # Разбиение набора данных на тренировочный и тестовый
    data_train, data_test = np.split(df, [int(0.7 * len(df))])

    # Обучение модуля для каждой из атак
    for j in range(number_of_attacks):
        data_train_with_attack = [(data_train[labels].iloc[i], data_train[names_with_attack[j]].iloc[i]) for i in range(data_train.shape[0])]
        ms.train_modules((data_train_with_attack, data_train.service[0], names[j]), 20)

    # Проверка работоспособности системы на тестовых данных
    predications = ms.predict((data_test[labels], data_test.service.iloc[0]))

    mas = []

    with open('temp.txt', 'w') as temp:
        for module in ms.modules:
            for w in module[2].weights:
                for l in w:
                    p = np.absolute(l)
                    temp.write(str(np.argmax(p)))
                    temp.write('\n\n')
                    mas.append(np.argmax(p))
                    #print(l)
            temp.write('\n')

    print(max(set(mas), key = mas.count))


    # Перевод числовых вероятностей принадлежности классам атак в метки классов
    data_test['type_of_attack'] = 'normal'
    for i in range(len(predications[0][0])):
        for j in range(number_of_attacks):
            if predications[j][0][i] > 0.5 and data_test['type_of_attack'].iloc[i] == 'normal':
                data_test['type_of_attack'].iloc[i] = names[j]

    # Запись файла с результами работы системы
    with open('result.csv', 'w', newline="") as result_file:
        fieldnames = df.columns.to_list()[:3] + ['type_of_attack']
        result_file.write(data_test[fieldnames].to_csv(index=False))

    #Анализ результата классификации как бинарной
    metrics = []
    for i in range(number_of_attacks):
        probabilities = predications[i][0]
        name_attack = predications[i][1]

        # Построение матрицы ошибок
        TP, FP, TN, FN = 0, 0, 0, 0
        check = data_test[names_with_attack[i]].to_list()
        for i in range(len(probabilities)):
            if probabilities[i] >= 0.5 and check[i] == 1:
                TP+=1
            elif probabilities[i] >= 0.5 and check[i] == 0:
                FP+=1
            elif probabilities[i] < 0.5 and check[i] == 1:
                FN+=1
            elif probabilities[i] < 0.5 and check[i] == 0:
                TN+=1

        # Расчет метрик для каждого модуля
        accuracy = (TP+TN)/(TP+FP+FN+TN) * 100
        precision = (TP)/(TP+FP) * 100
        recall = (TP)/(TP+FN) * 100
        f_measure = ((2 * precision * recall) / (precision + recall))
        type_1_errors = (FP)/(TP+FP+FN+TN) * 100
        type_2_errors = (FN)/(TP+FP+FN+TN) * 100

        metrics.append((accuracy, precision, recall, f_measure, type_1_errors, type_2_errors))
        
        print('~'*10, name_attack, '~'*20)
        print('Доля правильных ответов:\t\t%.2f\t%%' % accuracy)
        print('Точность:\t\t\t\t%.2f\t%%' % precision)
        print('Чувствительность:\t\t\t%.2f\t%%' % recall)
        print('F-мера:\t\t\t\t\t%.2f\t%%' % f_measure)
        print('Вероятнось ошибки 1-го рода:\t\t%.2f\t%%' % type_1_errors)
        print('Вероятнось ошибки 2-го рода:\t\t%.2f\t%%' % type_2_errors)

    #Расчет общих метрик системы
    accuracis = [attack_metric[0] for attack_metric in metrics]
    precisions = [attack_metric[1] for attack_metric in metrics]
    recalls = [attack_metric[2] for attack_metric in metrics]
    f_measures = [attack_metric[3] for attack_metric in metrics]
    types_1_errors = [attack_metric[4] for attack_metric in metrics]
    types_2_errors = [attack_metric[5] for attack_metric in metrics]

    avg_accuracy = np.mean(accuracis)
    avg_precision = np.mean(precisions)
    avg_recall = np.mean(recalls)
    avg_f_measure = np.mean(f_measures)
    avg_type_1_errors = np.mean(types_1_errors)
    avg_type_2_errors = np.mean(types_2_errors)
    
    print('~'*10,'Вся система','~'*20)
    print('Общая доля правильных ответов:\t\t%.2f\t%%' % avg_accuracy)
    print('Общая точность:\t\t\t\t%.2f\t%%' % avg_precision)
    print('Общая чувствительность:\t\t\t%.2f\t%%' % avg_recall)
    print('Общая f-мера:\t\t\t\t%.2f\t%%' % avg_f_measure)
    print('Общая вероятнось ошибки 1-го рода:\t%.2f\t%%' % avg_type_1_errors)
    print('Общая вероятнось ошибки 2-го рода:\t%.2f\t%%' % avg_type_2_errors)


if __name__ == '__main__':
    #Тестирование модуля обнаружения атак
    network_traffic_classification()