from numpy import zeros, std, mean, append
from numpy.random import randn, standard_normal
from numpy.ma import dot
from multiprocessing import Pool


class MyCMAEvolutionStrategy:
    def __init__(self, problem_shape, fitness_metric, sample_population_size=20):
        self.problem_dimension = problem_shape
        self.fitness_metric = fitness_metric
        self.sample_population_size = sample_population_size
        self.mean_solution = standard_normal(problem_shape)  # initial guess
        self.mean_solutions_fitness = self.get_mean_solutions_fitness()
        self.noise_factor = 1

    def train(self, fitness_requirement):
        generation_index = 0
        print("Original guesses fitness", self.mean_solutions_fitness)
        print("\n")
        while self.mean_solutions_fitness < fitness_requirement:
            print("Generation", generation_index)

            self.noise_factor = self.get_noise_factor(fitness_requirement)
            noises = self.get_noises()
            samples = noises + (self.mean_solution * self.noise_factor)

            pool = Pool()
            sample_rewards = pool.map(self.get_fitness_of_sample, [sample for sample in samples])
            print("sample rewards", sample_rewards)

            # rewards_including_means_reward = append(sample_rewards, self.mean_solutions_fitness)
            mean_of_rewards = mean(sample_rewards)
            standard_deviation_of_rewards = std(sample_rewards)
            weighted_rewards = pool.starmap(self.get_weighted_reward,
                                            ([(sample_reward, mean_of_rewards, standard_deviation_of_rewards)
                                              for sample_reward in sample_rewards]))
            pool.close()
            pool.join()
            print("sample weighted rewards", weighted_rewards)

            self.mean_solution += self.get_direction_to_head_towards(samples, weighted_rewards).transpose()
            self.mean_solutions_fitness = self.get_mean_solutions_fitness()

            print("population size", self.sample_population_size)
            print("noise factor", self.noise_factor)
            print("mean solution\n", self.mean_solution)
            print("mean solution's fitness: %s" % (str(self.mean_solutions_fitness)))
            print('\n\n===================================\n')
            generation_index += 1
        return self.mean_solution

    def train_without_multiprocessing(self, fitness_requirement):
        generation_index = 0
        print("Original guesses fitness", self.mean_solutions_fitness)
        print("\n")
        while self.mean_solutions_fitness < fitness_requirement:
            print("Generation", generation_index)

            self.noise_factor = self.get_noise_factor(fitness_requirement)
            noises = self.get_noises()
            samples = noises + self.mean_solution

            sample_rewards = self.get_fitness_of_samples(samples)
            weighted_rewards = self.get_weighted_rewards(sample_rewards)

            self.mean_solution += self.get_direction_to_head_towards(samples, weighted_rewards)
            self.mean_solutions_fitness = self.get_mean_solutions_fitness()

            print("population size", self.sample_population_size)
            print("noise factor", self.noise_factor)
            print("mean solution", self.mean_solution)
            print("mean solution's fitness: %s" % (str(self.mean_solutions_fitness)))
            print('\n\n===================================\n')

            generation_index += 1
        return self.mean_solution

    def get_mean_solutions_fitness(self):
        return self.fitness_metric.get_fitness(self.mean_solution)

    def get_direction_to_head_towards(self, samples, weighted_rewards):
        directions = samples - self.mean_solution
        directions /= self.noise_factor
        direction_to_head = dot(directions.transpose(), weighted_rewards) / self.sample_population_size
        return direction_to_head

    def get_noise_factor(self, fitness_requirement):
        noise_factor = (self.mean_solutions_fitness / fitness_requirement)
        return noise_factor

    def get_fitness_of_samples(self, samples):
        return [self.get_fitness_of_sample(sample) for sample in samples]

    def get_fitness_of_sample(self, sample):
        return self.fitness_metric.get_fitness(sample)

    def get_weighted_rewards(self, samples_rewards):
        weighted_rewards = (((samples_rewards - mean(samples_rewards))
                             / std(samples_rewards)))  # / (self.noise_factor * self.sample_population_size))
        return weighted_rewards

    def get_weighted_reward(self, sample_reward, mean_sample_reward, standard_deviation_of_rewards):
        sample_weighed_reward = ((sample_reward - mean_sample_reward) / (
            standard_deviation_of_rewards))
        return sample_weighed_reward

    def get_noises(self):
        random_noises = [(standard_normal(self.problem_dimension) * self.noise_factor)
                         for sample in range(self.sample_population_size)]
        return random_noises
