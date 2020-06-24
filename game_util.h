#define GRID_WIDTH 7
#define GRID_HEIGHT 6
#define COMMAND_SIZE 128

#define PLAYER 1
#define NO_PLAYER 0
#define OPPONENT -1

#define GAME_END_CORRECT 1
#define GAME_END_ERROR 0

// parameters passed by client's main
extern char* player_nickname;
extern char* opponent_nickname;
extern unsigned char* key;
extern int sock;

void handle_msg(int msg);
int game_run(char* p_n, char* o_n, unsigned char* symmetric_key, int so, int slave);