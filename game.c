#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    if (player != 1 && player != -1) {
        EXCEPTION("player must be either 1 or -1", __func__);
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
                case 1:
                    printf("O");
                    break;
                case -1:
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

int check_win(int* game_grid, int last_row, int last_col) {
    for()
}

int main() {
    int* game_grid = (int*)malloc(GRID_HEIGHT * GRID_WIDTH * sizeof(int));
    memset(game_grid, 0, GRID_HEIGHT * GRID_WIDTH * sizeof(int));

    char* buffer = (char*)malloc(COMMAND_SIZE);
    char* command = (char*)malloc(COMMAND_SIZE);
    int param;

    int msg = MSG_OK;

    system("clear");

    while (1) {
        // print game screen
        print_game_grid(game_grid);
        if (msg != MSG_OK) {
            handle_msg(msg);
            msg = MSG_OK;
        }
        printf("> ");

        // clear buffers for storing commands
        memset(buffer, 0, COMMAND_SIZE);
        memset(command, 0, COMMAND_SIZE);
        param = -1;

        // read commands from user's input
        fgets(buffer, COMMAND_SIZE, stdin);
        sscanf(buffer, "%s", command);
        sscanf(buffer + strlen(command), "%d", &param);

        // decode the inserted command and handle msgs
        if (strcmp(command, "insert") == 0) {
            msg = insert_checker(game_grid, 1, param);
        } else if (strcmp(command, "help") == 0) {
            msg = MSG_SHOW_GUIDE;
        } else if (strcmp(command, "quit") == 0) {
            break;
        } else {
            msg = MSG_COMMAND_NOT_FOUND;
        }

        system("clear");
    }
}