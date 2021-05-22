
import * as hostile from 'hostile';
import { CLI } from 'tnp-cli';
import { net } from 'tnp-core';

export class Hostile {

  /**
   * Display all current ip records
   */
  list() {
    var lines
    try {
      lines = hostile.get(false)
    } catch (err) {
      return this.error(err)
    }
    lines.forEach((item) => {
      if (item.length > 1) {
        console.log(item[0], CLI.chalk.green(item[1]))
      } else {
        console.log(item)
      }
    })
  }

  /**
   * Set a new host
   * @param {string} ip
   * @param {string} host
   */
  set(ip, host) {
    if (!ip || !host) {
      return this.error('Invalid syntax: hostile set <ip> <host>')
    }

    if (ip === 'local' || ip === 'localhost') {
      ip = '127.0.0.1'
    } else if (!net.isIP(ip)) {
      return this.error('Invalid IP address')
    }

    try {
      hostile.set(ip, host)
    } catch (err) {
      return this.error('Error: ' + err.message + '. Are you running as root?')
    }
    console.log(CLI.chalk.green('Added ' + host))
  }

  /**
   * Remove a host
   * @param {string} host
   */
  remove(host) {
    var lines
    try {
      lines = hostile.get(false)
    } catch (err) {
      return this.error(err)
    }
    lines.forEach((item) => {
      if (item[1] === host) {
        try {
          hostile.remove(item[0], host)
        } catch (err) {
          return this.error('Error: ' + err.message + '. Are you running as root?')
        }
        console.log(CLI.chalk.green('Removed ' + host))
      }
    })
  }

  /**
   * Load hosts given a file
   * @param {string} filePath
   */
  load(filePath) {
    var lines = this.parseFile(filePath)

    lines.forEach((item) => {
      this.set(item[0], item[1])
    })
    console.log(CLI.chalk.green('\nAdded %d hosts!'), lines.length)
  }

  /**
   * Remove hosts given a file
   * @param {string} filePath
   */
  unload(filePath) {
    var lines = this.parseFile(filePath)

    lines.forEach((item) => {
      this.remove(item[1])
    })
    console.log(CLI.chalk.green('Removed %d hosts!'), lines.length)
  }

  /**
   * Get all the lines of the file as array of arrays [[IP, host]]
   * @param {string} filePath
   */
  parseFile(filePath) {
    var lines
    try {
      lines = hostile.getFile(filePath, false)
    } catch (err) {
      return this.error(err)
    }
    return lines
  }

  /**
   * Print an error and exit the program
   * @param {string} message
   */
  error(err) {
    console.error(CLI.chalk.red(err.message || err))
    process.exit(-1)
  }

}
