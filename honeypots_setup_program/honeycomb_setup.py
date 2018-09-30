from subprocess import run

if __name__ == "__main__":
    run(["pip3", "install", "honeycomb-framework"])
    run(["export", "LC_ALL=C.UTF-8"])
    run(["export", "LANG=C.UTF-8"])
    run(["cd", "/home"])
    run(["git", "clone", "https://github.com/h4nek/honeycomb_plugins.git"])
    run(["cp", "-r", "honeycomb_plugins", "/root/.config/honeycomb/"])
    run(["honeycomb", "--iamroot", "service", "run"])
    #run(["apt", "install", "git-all"])
