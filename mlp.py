import numpy as np
import math
import random

class MLP:
    def __init__(self, init_neurons = 0, learning_rate = .1):
        """
        Creating a new neural network - multi-layer perceptron

        Args:
            init_neurons (int, optional): Number of neurons in the input layer. Defaults to 0.
            learning_rate (float, optional): Neural network learning rate. Defaults to 0.1.
        """
        self.number_of_neurons = []
        if init_neurons > 0:
            self.number_of_neurons.append(init_neurons)
        self.weights = []
        self.biases = []
        self.functions = []
        self.learning_rate = learning_rate


    def add_layer(self, number_of_neurons, weights = None, bias = None, function ="soft_plus"):
        """
        Add a new layer to the perceptron

        Args:
            number_of_neurons (integer): Number of neurons in the current layer
            weights (list, optional): Weights matrix for the current layer. Defaults to None.
            bias (list, optional): Biases vector for the current layer. Defaults to None.
            function (str, optional): Name of the activation function(soft_plus,sigmoid,relu). Defaults to "soft_plus".
        """
        self.number_of_neurons.append(number_of_neurons)

        if not weights is None:
            self.weights.append(weights)
            self.functions.append(function)
        elif len(self.number_of_neurons) > 1:
            self.weights.append(np.random.randn(self.number_of_neurons[-1], self.number_of_neurons[-2]))
            self.functions.append(function)

        if not bias is None:
            self.biases.append(bias)
        elif len(self.number_of_neurons) > 1:
            self.biases.append(np.random.random_sample((number_of_neurons, 1)))


    @staticmethod
    def soft_plus(x):
        sp = np.vectorize(lambda y: math.log(1 + math.exp(y)))
        return sp(x)


    @staticmethod
    def relu(x):
        re = np.vectorize(lambda y: max(0, y))
        return re(x)


    @staticmethod
    def sigmoid(x):
        sig = np.vectorize(lambda y:  (1 / (1 + math.exp(-y))))
        return sig(x)
    

    @staticmethod
    def activation(x, function):
        if function == "sigmoid":
            return MLP.sigmoid(x)
        elif function == "soft_plus":
            return MLP.soft_plus(x)
        elif function == "relu":
            return MLP.relu(x)


    @staticmethod
    def derivative(x, function):
        if function == "sigmoid":
            return np.multiply(MLP.sigmoid(x), (1-MLP.sigmoid(x)))
        elif function == "soft_plus":
            return MLP.sigmoid(x)
        elif function == "relu":
            d_relu = np.vectorize(lambda y: 1 if y > 0 else 0)
            return d_relu(x)


    def feed_forward(self, input):
        outputs = [np.matrix(input).T]

        for i in range(len(self.number_of_neurons) - 1):
            outputs.append(MLP.activation((np.dot(self.weights[i], outputs[-1]) + self.biases[i]), self.functions[i]))

        return outputs

    
    def train(self, data, epochs = 1, eps = 0.4, show_statistics = True):
        """
        Perceptron training

        Args:
            data (list): List of input and target values
            epochs (int, optional): Number of training epochs. Defaults to 1.
            eps (float, optional): Acceptable value of the neural network error. Defaults to 0.4.
            show_statistics (bool, optional): Output training information by epoch. Defaults to True.
        """
        if show_statistics:
            print("Training the network...")
        
        for epoch in range(epochs):
            if show_statistics:
                print("Epoch №", epoch + 1)

            random.shuffle(data)
            data_errors = []
            for i in range(len(data)):
                targets_data = data[i][1]
                input_data = data[i][0]

                targets_data = np.matrix(targets_data).T
                
                outputs_data = self.feed_forward(input_data)

                errors = [targets_data - outputs_data[-1]]
                data_errors.append(errors[0][0][0])

                for i in range(len(self.weights) - 1):
                    errors.insert(0, np.dot(self.weights[-1-i].T, errors[0]))

                for i in range(len(self.weights)):
                    gradient = np.multiply(errors[-1-i], MLP.derivative(outputs_data[-1-i], self.functions[-1-i])) * self.learning_rate
                    self.biases[-1-i] += gradient

                    delta_w  = np.dot(gradient, outputs_data[-2-i].T)
                    self.weights[-1-i] += delta_w
                
            if max(data_errors) < eps:
                if show_statistics:
                    print("Training is over2.")
                return
        if show_statistics:
            print("Training is over.")
        


    def predict(self, input):
        output = self.feed_forward(input)[-1]
        output = dict(enumerate(output.A1))
        out_prob = list(output.values())
        
        return out_prob
