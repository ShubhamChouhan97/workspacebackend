/* eslint-disable camelcase */

exports.shorthands = undefined;

exports.up = async pgm => {
    await pgm.sql(`ALTER TABLE users
        ADD COLUMN IF NOT EXISTS last_active VARCHAR(10) DEFAULT NULL
        `);
};

exports.down = pgm => {};
