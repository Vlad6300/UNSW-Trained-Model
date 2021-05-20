# UNSW-Trained-Model

The drl.tar file is a Docker container that provides a working environment, the code and the data.

## How to use
After installing and running the docker container, you will find a python script labeled sample_code_main.py in the container. 
Run this script with any of the following options:

![image](https://user-images.githubusercontent.com/29517124/118824733-c26cab80-b8c2-11eb-976e-af7bdf7f3a61.png)

The provided trained models are stored in the files NO-PORT-MODEL, PORT-53-MODEL and PORT-80-MODEL.

The sample encoded data is stored in the files NO-PORT_Encoded_UNSW.csv, PORT-53_Encoded_UNSW.csv and PORT-80_Encoded_UNSW.csv.

Other python files are used in running the script:
sample_agent - defines a DRL agent
sample_classifer - defines the NN used
sample_env - defines the environment of the agent
stats_getter - outputs the data
