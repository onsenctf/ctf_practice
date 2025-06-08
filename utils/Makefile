TARGET_DIR := $$HOME/opt/bin
TARGET_BIN := writeup

all: $(TARGET_BIN)

$(TARGET_BIN): writeup.sh
	@if echo $$PATH | grep -q $(TARGET_DIR); then \
		mkdir -p $(TARGET_DIR); \
		ln -sf $$PWD/$< $(TARGET_DIR)/$@; \
		chmod +x $(TARGET_DIR)/$@; \
	else \
		echo $(TARGET_DIR)を'$$PATH'に追加してください。; \
	fi

clean:
	rm $$HOME/opt/bin/$(TARGET_BIN)
