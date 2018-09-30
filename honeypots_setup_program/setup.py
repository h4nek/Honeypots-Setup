from subprocess import run

#from distutils.core import setup
"""
setup(name='honeypots_setup_program',
      version='0.5',
      py_modules=['json', 'subprocess', 'time', 'copy', 'random']
     )
"""
if __name__ == "__main__":
    run(["modprobe", "dummy"], stdout=DEVNULL, stderr=STDOUT)# load dummy kernel module if it's not loaded
    
    run(["docker", "build", "-t", "honeypots_setup", "."])
    run(["docker", "run", "-it", "honeypots_setup"])
    
