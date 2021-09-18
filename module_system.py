from mlp import MLP

class ModuleSystem:
    def __init__(self):
        """
        Создание системы модулей распознования сетевых атак
        """
        self.modules = []

    def add_detection_module(self, attack_name, type_of_attack_service, number_of_features):
        """
        Добавление обнаруживающего модуля - нейронной сети

        Args:
            attack_name (str): Имя атаки
            type_of_attack_service (str): Протокол прикладного уровня, на котором будет атака
            number_of_features (int): Количество признаков сессий
        """
        perceptron = MLP(init_neurons = number_of_features, learning_rate = 0.01)
        perceptron.add_layer(number_of_neurons = number_of_features, function='soft_plus')
        perceptron.add_layer(number_of_neurons = 1, function='soft_plus')

        self.modules.append((attack_name, type_of_attack_service, perceptron))

    def train_modules(self, train_data, count_of_epochs, statistics = True):
        """
        Тренировка системы модулей

        Args:
            train_data (tuple): Кортеж с набором данных для обучения, протоколом и именем атаки
            count_of_epochs (int): Количество эпох обучения модулей
            statistics (bool, optional): Флаг вывод подробной информации. Defaults to True.
        """
        for attack_name, type_of_attack_service, module in self.modules:
            dataset, service, name = train_data
            if service == type_of_attack_service and name == attack_name:
                module.train(dataset, count_of_epochs, show_statistics = statistics)

    def predict(self, traffic_data):
        """
        Обнаружение атак в поданных данных

        Args:
            traffic_data (tuple): Кортеж с набором данных для распознования, протоколом и именем атаки

        Returns:
            [list]: Массив с векторами вероятностей принадлежности каждой сессии каждой из разпозноваемых атак
        """
        probabilities_of_attacks = []
        for attack_name, type_of_attack_service, module in self.modules:
            dataset, service = traffic_data
            if service == type_of_attack_service:
                probabilities_of_attacks.append((module.predict(dataset), attack_name))
        
        return probabilities_of_attacks