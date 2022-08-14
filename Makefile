COMPILER = gcc
CFLAGS   = -O2 -MMD -MP -Wall -Wextra
LDFLAGS  = 
LIBDIR   = ./libs
LIBS     = $(LIBDIR)/librawframe.a
INCLUDE  = -I./include
TARGET   = target
SRCDIR   = ./src
OBJDIR   = ./obj
SOURCES  = $(wildcard $(SRCDIR)/*.c)
OBJECTS  = $(addprefix $(OBJDIR)/, $(notdir $(SOURCES:.c=.o)))
DEPENDS  = $(OBJECTS:.o=.d)

.PHONY: all clean

all: $(TARGET)

-include $(DEPENDS)

$(TARGET): $(OBJECTS) $(LIBS)
	$(COMPILER) -o $@ $^ $(LDFLAGS)

$(LIBS):
	make COMPILER="$(COMPILER)" LDFLAGS="$(LDFLAGS)" -C $(LIBDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@if [ ! -e $(OBJDIR) ]; then mkdir -p $(OBJDIR); fi
	$(COMPILER) -o $@ $(CFLAGS) $(INCLUDE) -c $<

clean:
	make clean -C $(LIBDIR)
	rm -rf $(OBJECTS) $(DEPENDS) $(TARGET) $(OBJDIR)
	rm -f *~
