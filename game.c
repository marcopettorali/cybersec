#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "game_util.h"
#include "util.h"

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
                    printf("O");
                    break;
                case OPPONENT:
                    printf("X");
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
            int counter_backward = 0;
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

int main() {
    int* game_grid = (int*)malloc(GRID_HEIGHT * GRID_WIDTH * sizeof(int));
    memset(game_grid, 0, GRID_HEIGHT * GRID_WIDTH * sizeof(int));

    char* buffer = (char*)malloc(COMMAND_SIZE);
    char* command = (char*)malloc(COMMAND_SIZE);
    int column;

    int msg = MSG_OK;

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

                int winner = check_win(game_grid, column);
                if (winner == PLAYER) {
                    system("clear");
                    print_game_grid(game_grid);
                    printf("YOU WIN!\n");
                    break;
                } else if (winner == OPPONENT) {
                    system("clear");
                    print_game_grid(game_grid);
                    printf("The opponent has won the match\n");
                    break;
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
}