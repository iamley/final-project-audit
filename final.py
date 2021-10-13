#!/usr/bin/env python
# coding: utf-8

# In[7]:


import tkinter as tk
from tkinter import ttk
from tkinter import *
from tkinter.ttk import *
from tkinter import scrolledtext as st
import sys
from tkinter import filedialog as fd
from tkinter import messagebox as mb

class Monitor:

    def __init__(self, window):
        # Initializations 
        self.wind = window
        self.wind.title('Network Monitor')
        self.scrolledtext1=st.ScrolledText(self.wind, width=100, height=10)
        self.scrolledtext1.pack(fill=tk.BOTH, side=tk.LEFT, expand=True)
        
if __name__ == '__main__':
    window = tk.Tk()
    application = Monitor(window)
    window.mainloop()


# In[ ]:





# In[ ]:




