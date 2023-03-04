# yt2mp3
Downloads best quality audio from YouTube.com and converts the file to mp3 while preserving the original bitrate and sample rate.

**Full disclosure**, I did not write the code for lines 115 through 669. That part came from [youtube-dl](https://github.com/ytdl-org/youtube-dl).  
*Specifically, from [here](https://github.com/ytdl-org/youtube-dl/blob/master/youtube_dl/extractor/youtube.py).*  

**Additionally**, this script uses [ffmpeg-python](https://github.com/kkroening/ffmpeg-python) to convert the audio file (usually webm) to an mp3 file.  
  
## Installation
If you're on any debian-based GNU/Linux, then use the following script to install the necessary packages required to use **yt2mp3.py**
```sh
sudo apt update && sudo apt install python python-pip libxml2 libxslt ffmpeg git -y
git clone https://github.com/nstevens1040/yt2mp3.git && cd yt2mp3/
pip install -r requirements.txt
```  

## Usage
```sh
python3 yt2mp3.py <youtube video link>
```  
