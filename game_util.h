#define GRID_WIDTH 7
#define GRID_HEIGHT 6
#define COMMAND_SIZE 128

#define PLAYER 1
#define NO_PLAYER 0
#define OPPONENT -1

#define MSG_OK 1
#define MSG_COMMAND_NOT_FOUND 0
#define MSG_COLUMN_FULL -1
#define MSG_COLUMN_NOT_VALID -2
#define MSG_SHOW_GUIDE -3

void handle_msg(int msg);