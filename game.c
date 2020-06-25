#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "game_net.h"
#include "game_util.h"
#include "util.h"

// parameters passed by client's main
char* player_nick;
char* opponent_nick;
unsigned char* key;
int sock;

//---- GRID UTIL ----//
int get_element_at(int* game_grid, int row, int col) {
    if (row < 0 || row >= GRID_HEIGHT) {
        EXCEPTION("row boundaries exceeded", __func__);
    }
    if (col < 0 || col >= GRID_WIDTH) {
        EXCEPTION("column boundaries exceeded", __func__);
    }
    if (game_grid == NULL) {
        EXCEPTION("game grid null", __func__);
    }
    return *(game_grid + row * GRID_WIDTH + col);
}

void put_element_at(int* game_grid, int value, int row, int col) {
    if (row < 0 || row >= GRID_HEIGHT) {
        EXCEPTION("row boundaries exceeded", __func__);
    }
    if (col < 0 || col >= GRID_WIDTH) {
        EXCEPTION("column boundaries exceeded", __func__);
    }
    if (game_grid == NULL) {
        EXCEPTION("game grid null", __func__);
    }

    *(game_grid + row * GRID_WIDTH + col) = value;
}

int is_column_full(int* game_grid, int col) {
    if (col < 0 || col >= GRID_WIDTH) {
        EXCEPTION("column boundaries exceeded", __func__);
    }
    return (get_element_at(game_grid, 0, col) != 0);
}

int insert_checker(int* game_grid, int player, int col) {
    if (col < 0 || col >= GRID_WIDTH) {
        return MSG_COLUMN_NOT_VALID;
    }
    if (player != PLAYER && player != OPPONENT) {
        EXCEPTION("player not valid", __func__);
    }
    if (is_column_full(game_grid, col)) {
        return MSG_COLUMN_FULL;
    }

    for (int i = GRID_HEIGHT - 1; i >= 0; i--) {
        if (get_element_at(game_grid, i, col) == 0) {
            put_element_at(game_grid, player, i, col);
            return 1;
        }
    }
    return MSG_OK;
}

int cell_exists(int row, int col) {
    if (row < 0 || row >= GRID_HEIGHT) {
        return 0;
    }
    if (col < 0 || col >= GRID_WIDTH) {
        return 0;
    }
    return 1;
}

//----- GRAPHICS -----//
void print_straight_line() {
    for (int i = 0; i < GRID_WIDTH * 4 + 1; i++) {
        printf("-");
    }
    printf("\n");
}
void print_game_grid(int* game_grid) {
    for (int i = 0; i < GRID_HEIGHT; i++) {
        print_straight_line();
        for (int j = 0; j < GRID_WIDTH; j++) {
            printf("| ");
            switch (get_element_at(game_grid, i, j)) {
                case PLAYER:
                    printf(GREEN "O" RESET);
                    break;
                case OPPONENT:
                    printf(RED "X" RESET);
                    break;
                default:
                    printf(" ");
                    break;
            }
            printf(" ");
        }
        printf("|\n");
    }
    print_straight_line();
    for (int i = 0; i < GRID_WIDTH; i++) {
        printf("  %d ", i);
    }
    printf("\n");
}

int check_win(int* game_grid, int last_col) {
    int last_player;
    int last_row;
    for (int i = 0; i < GRID_HEIGHT; i++) {
        last_player = get_element_at(game_grid, i, last_col);
        if (last_player != NO_PLAYER) {
            last_row = i;
            break;
        }
    }
    int x_vec, y_vec;
    for (x_vec = -1; x_vec <= 1; x_vec++) {
        for (y_vec = -1; y_vec <= 1; y_vec++) {
            if (x_vec == 0 && y_vec == 0) {
                continue;
            }
            int counter = 1;  // the central cell contains a checker
            int curr_row = last_row + y_vec;
            int curr_col = last_col + x_vec;
            while (cell_exists(curr_row, curr_col) && get_element_at(game_grid, curr_row, curr_col) == last_player) {
                counter++;
                curr_row += y_vec;
                curr_col += x_vec;
            }
            curr_row = last_row - y_vec;
            curr_col = last_col - x_vec;
            while (cell_exists(curr_row, curr_col) && get_element_at(game_grid, curr_row, curr_col) == last_player) {
                counter++;
                curr_row -= y_vec;
                curr_col -= x_vec;
            }
            if (counter == 4) {
                return last_player;
            }
        }
    }
    return NO_PLAYER;
}

int game_run(char* p_n, char* o_n, unsigned char* symmetric_key, int so, int slave) {
    player_nick = p_n;
    opponent_nick = o_n;
    key = symmetric_key;
    sock = so;

    int* game_grid = (int*)malloc(GRID_HEIGHT * GRID_WIDTH * sizeof(int));
    memset(game_grid, 0, GRID_HEIGHT * GRID_WIDTH * sizeof(int));

    char* buffer = (char*)malloc(COMMAND_SIZE);
    char* command = (char*)malloc(COMMAND_SIZE);
    int column;

    int msg = MSG_OK;

    int move_counter = 0;
    if (slave == 1) {
        printf("Waiting for the opponent's move...");
        char player_1[NICKNAME_LENGTH];
        char player_2[NICKNAME_LENGTH];
        char count;
        char column;
        if (wait_move(&player_1[0], &player_2[0], &count, &column) != OK) {
            return GAME_END_ERROR;
        }
        if (count != 0) {
            printf("error: move_counter = %d, count = %d\n", move_counter, count);
            return GAME_END_ERROR;
        }
        move_counter = count + 1;
        if (strcmp(&player_1[0], &opponent_nick[0]) != 0 || strcmp(&player_2[0], &player_nick[0]) != 0) {
            printf("error: player1 = %s, player 2 = %s\n", player_1, player_2);
            return GAME_END_ERROR;
        }
        int ret = insert_checker(game_grid, OPPONENT, column);
        if (ret != MSG_OK) {
            printf("error: msg = %d\n", ret);
            return GAME_END_ERROR;
        }
    }

    while (1) {
        // print game screen
        system("clear");
        print_game_grid(game_grid);
        if (msg != MSG_OK) {
            handle_msg(msg);
            msg = MSG_OK;
        }
        printf("> ");

        // clear buffers for storing commands
        memset(buffer, 0, COMMAND_SIZE);
        memset(command, 0, COMMAND_SIZE);
        column = -1;

        // read commands from user's input
        fgets(buffer, COMMAND_SIZE, stdin);
        sscanf(buffer, "%s", command);
        sscanf(buffer + strlen(command), "%d", &column);

        // decode the inserted command and handle msgs
        if (strcmp(command, "insert") == 0) {
            msg = insert_checker(game_grid, PLAYER, column);
            if (msg == MSG_OK) {
                system("clear");
                print_game_grid(game_grid);
                send_move(&player_nick[0], &opponent_nick[0], move_counter, column);
                int winner = check_win(game_grid, column);
                if (winner == PLAYER) {
                    system("clear");
                    print_game_grid(game_grid);
                    printf(YELLOW "YOU WIN!\n" RESET);
                    break;
                } else {
                    char player_1[NICKNAME_LENGTH];
                    char player_2[NICKNAME_LENGTH];
                    char count;
                    char column;
                    printf("waiting for the opponent's move...\n");
                    if (wait_move(&player_1[0], &player_2[0], &count, &column) != OK) {
                        return GAME_END_ERROR;
                    }
                    if (count != move_counter + 1) {
                        printf("error: move_counter = %d, count = %d\n", move_counter, count);
                        return GAME_END_ERROR;
                    }
                    move_counter = count + 1;
                    if (strcmp(&player_1[0], &opponent_nick[0]) != 0 || strcmp(&player_2[0], &player_nick[0]) != 0) {
                        printf("error: player1 = %s, player 2 = %s\n", player_1, player_2);
                        return GAME_END_ERROR;
                    }

                    int ret = insert_checker(game_grid, OPPONENT, column);
                    if (ret != MSG_OK) {
                        printf("error: msg = %d\n", ret);
                        return GAME_END_ERROR;
                    }
                    int win = check_win(game_grid, column);
                    if (win == OPPONENT) {
                        system("clear");
                        print_game_grid(game_grid);
                        printf( MAGENTA "The opponent won the match\n" RESET);
                        break;
                    }
                }
            }
        } else if (strcmp(command, "help") == 0) {
            msg = MSG_SHOW_GUIDE;
        } else if (strcmp(command, "quit") == 0) {
            break;
        } else {
            msg = MSG_COMMAND_NOT_FOUND;
        }
    }
    free(game_grid);
    free(buffer);
    free(command);
    return GAME_END_CORRECT;
}