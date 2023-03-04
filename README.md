# yt2mp3
Downloads best quality audio from YouTube.com and converts the file to mp3 while preserving the original bitrate and sample rate.

**Full disclosure**, I did not write the code for lines 115 through 669. That part came from [youtube-dl](https://github.com/ytdl-org/youtube-dl).  
*Specifically, from [here](https://github.com/ytdl-org/youtube-dl/blob/master/youtube_dl/extractor/youtube.py).*  

**Additionally**, this script uses [ffmpeg-python](https://github.com/kkroening/ffmpeg-python) to convert the audio file (usually webm) to an mp3 file.  
  
## Usage
```sh
python3 yt2mp3.py <youtube video link>
```  
