from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.gridlayout import GridLayout


class Main(GridLayout):
    def __init__(self, **kwargs):
        super(Main, self).__init__(**kwargs)
        self.cols = 1
        self.mini_layout = GridLayout
        self.mini_layout = GridLayout(cols=4)
        self.button1 = Button(text="1")
        self.button2 = Button(text="2")
        self.button3 = Button(text="3")
        self.button4 = Button(text="4")
        self.button5 = Button(text="5")
        self.button6 = Button(text="6")
        self.button7 = Button(text="7")
        self.button8 = Button(text="8")
        self.button9 = Button(text="9")
        self.button0 = Button(text="0")
        self.buttonC = Button(text="C")
        self.button_go = Button(text="=")
        self.button_m = Button(text="x")
        self.button_s = Button(text="-")
        self.button_a = Button(text="+")
        self.button_d = Button(text="÷")


        self.mini_layout.add_widget(self.buttonC)
        self.mini_layout.add_widget(self.button0)
        self.mini_layout.add_widget(self.button_go)
        self.mini_layout.add_widget(self.button_a)
        self.mini_layout.add_widget(self.button1)
        self.mini_layout.add_widget(self.button2)
        self.mini_layout.add_widget(self.button3)
        self.mini_layout.add_widget(self.button_s)
        self.mini_layout.add_widget(self.button4)
        self.mini_layout.add_widget(self.button5)
        self.mini_layout.add_widget(self.button6)
        self.mini_layout.add_widget(self.button_m)
        self.mini_layout.add_widget(self.button7)
        self.mini_layout.add_widget(self.button8)
        self.mini_layout.add_widget(self.button9)
        self.mini_layout.add_widget(self.button_d)



        self.button1.bind(on_release = self.calc)
        self.button2.bind(on_release=self.calc)
        self.button3.bind(on_release=self.calc)
        self.button4.bind(on_release=self.calc)
        self.button5.bind(on_release=self.calc)
        self.button6.bind(on_release=self.calc)
        self.button7.bind(on_release=self.calc)
        self.button8.bind(on_release=self.calc)
        self.button9.bind(on_release=self.calc)
        self.button0.bind(on_release=self.calc)
        self.buttonC.bind(on_release=self.calc)
        self.button_go.bind(on_release=self.calc)
        self.button_s.bind(on_release=self.calc)
        self.button_m.bind(on_release=self.calc)
        self.button_a.bind(on_release=self.calc)
        self.button_d.bind(on_release=self.calc)





        self.label = TextInput(text = "0",readonly = True, font_size = 60)
        self.add_widget(self.label)
        self.add_widget((self.mini_layout))
        self.moder = "a"
        self.pops = "n"
        self.error = "at"



    def calc(self,instance):
        if instance == self.button1:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "1"
                self.pops = "d"
                self.error = ""
            else:
                self.label.text += "1"
                self.pops = "d"

        elif instance == self.button2:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "2"
                self.pops = "d"
                self.error = ""
            else:
                self.label.text += "2"
                self.pops = "d"

        elif instance == self.button3:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "3"
                self.pops = "d"
                self.error = ""
            else:
                self.label.text += "3"
                self.pops = "d"

        elif instance == self.button4:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "4"
                self.pops = "d"
                self.error = ""

            else:
                self.label.text += "4"
                self.pops = "d"

        elif instance == self.button5:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "5"
                self.pops = "d"
                self.error = ""
            else:
                self.label.text += "5"
                self.pops = "d"

        elif instance == self.button6:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "6"
                self.pops = "d"
                self.error = ""
            else:
                self.label.text += "6"
                self.pops = "d"

        elif instance == self.button7:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "7"
                self.pops = "d"
                self.error = ""
            else:
                self.label.text += "7"
                self.pops = "d"

        elif instance == self.button8:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "8"
                self.pops = "d"
                self.error = ""
            else:
                self.label.text += "8"
                self.pops = "d"

        elif instance == self.button9:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "9"
                self.pops = "d"
                self.error = ""
            else:
                self.label.text += "9"
                self.pops = "d"

        elif instance == self.button0:
            if self.label.text == "0" or self.error == "at":
                self.label.text = "0"
                self.pops = "d"
                self.error = ""
            else:
                self.label.text += "0"
                self.pops = "d"

        elif instance == self.buttonC:
            global moder
            if self.label.text == "0":
                self.label.text = "0"
            elif self.moder == "c":
                self.label.text = "0"
                self.moder = "a"
                self.pops = "n"
            else:
                self.label.text = self.label.text[:-1]

        elif instance == self.button_m:
            if self.pops == "d":
                if self.label.text == "0":
                     self.label.text = " x "
                     self.pops = "n"
                else:
                    self.label.text += " x "
                    self.pops = "n"

        elif instance == self.button_go:
            try:
                result = str(eval(self.label.text.replace("÷", "/").replace("x", "*")))
                self.label.text = result
                self.moder = "c"
            except Exception:
                self.label.text = "Error"
                self.error = "at"


        elif instance == self.button_a:
            if self.pops == "d":
                if self.label.text == "0":
                    self.label.text = " + "
                    self.pops = "n"

                else:
                    self.label.text += "+"
                    self.pops = "n"

        elif instance == self.button_d:
            if self.pops == "d":
                if self.label.text == "0":
                    self.label.text = " ÷ "
                    self.pops = "n"
                else:
                    self.label.text += "÷"
                    self.pops = "n"

        elif instance == self.button_s:
            if self.pops == "d":
                if self.label.text == "0":
                    self.label.text = "-"
                    self.pops = "n"
                else:
                    self.label.text += " - "
                    self.pops = "n"


class MainRun(App):
    def build(self):
        return Main()

if __name__ == "__main__":
    MainRun().run()
