from analyse_cpu import generalite_cpu
import time
import tkinter

class Sys_cpu_analyse():

    def __init__(self, nb_data = 20, time_sleep = 5,
                 nb_data_same = 5, same = 0.1,
                 nb_data_max = 15, max_sus = 95,
                 sur = True):
        """
        nb_data : le nombre de données sur lequel on fait l'analyse
            par def (20)

        time_sleep : le temps entre chaque observation du cpu
            par def (5s)

        nb_data_same : le nombre de données identiques a partir duquel
            on considère que c'est suspect.
            par def (5)

        same : l'écart qu'on tolère entre deux valeurs identiques.
            par def (0.1)

        nb_data_max : le nb de données au dessus du seuil
            a partir duquel on considère cela suspect
            par def (15)

        max_sus : le seuil a partir duquel on considère cela suspect.
            par def (95)

        sur : si on veut être informe des que l'un des critère est suspect
            (False) ou si on veut attendre que le deux le soit (True)
            par def True
        """
        self.nb_data = nb_data
        self.time_sleep = time_sleep
        self.data = []
        self.nb_data_same = nb_data_same
        self.same = same
        self.nb_data_max = nb_data_max
        self.max_sus = max_sus
        self.sur = sur

        #lancement
        self.main()

    def obtain_data(self):
        """
        Regarde min_data fois l'activité du CPU
        """
        for i in range(self.nb_data):
            self.data.append(generalite_cpu()[0])
            time.sleep(self.time_sleep)

    def analyse_same(self):
        """
        Cette fonction regarde les données et
        determine si il y a une activité suspect
        en regardantles variation d'activité du cpu

        renvoie True si suspect.
        """
        i = 0
        initial = self.data[0]
        for el in self.data[1:]:
            if initial - self.same < el and el< initial + self.same:
                i += 1
                if i == self.nb_data_same:
                    return True
            else:
                i = 0
                initial = el
        return False


    def analyse_intensity(self):
        """
        Cette fonction regarde l'intensité de l'utilisation du cpu
        pour déterminer si quelque chose de suspect tourne.
        """
        i = 0
        for el in self.data:
            if el>self.max_sus:
                i += 1
                if i == self.nb_data_max:
                    return True
        return False

    def main(self):
        """
        Le processus d'arrière plan.

        S'arrète quand après avoir annoncé qu'il y avait du minage.
        """
        minage = False
        while not minage:
            self.obtain_data()
            sus_same = self.analyse_same()
            sus_max = self.analyse_intensity()
            if self.sur:
                if sus_same and sus_max:
                    minage  = True
            else:
                if sus_max or sus_same:
                    minage = True

        # quand minage l'annoncé.
        msg = "Attention du code de minage tourne sur votre ordinateur"
        title = "Analyse du cpu"
        tkinter.messagebox.showwarning(title=title, message=msg)


#launch
Sys_cpu_analyse()