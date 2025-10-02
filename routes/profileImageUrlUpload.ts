/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns/promises'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      // SSRF protection: Only allow URLs from known safe domains
      const ALLOWED_IMAGE_HOSTS = [
        'imgur.com',
        'i.imgur.com',
        'images.unsplash.com',
        'cdn.pixabay.com'
        // Add other legitimate image hosts as needed
      ]
      async function isSafeImageUrl(imageUrl: string): Promise<boolean> {
        function isPrivateIp(ip: string): boolean {
          if (net.isIPv4(ip)) {
            return (
              ip.startsWith('10.') ||
              ip.startsWith('127.') ||
              ip.startsWith('169.254.') ||
              ip.startsWith('192.168.') ||
              /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)
            )
          }
          if (net.isIPv6(ip)) {
            // Link-local, unique-local, loopback, etc
            return (
              ip === '::1' ||
              ip.startsWith('fe80:') ||
              ip.startsWith('fc00:') ||
              ip.startsWith('fd00:')
            )
          }
          return false
        }
        try {
          const parsedUrl = new URL(imageUrl)
          // Enforce http(s) protocol
          if (!['http:', 'https:'].includes(parsedUrl.protocol)) return false
          const hostname = parsedUrl.hostname
          // Fast check for localhost, but don't rely on just string
          if (
            hostname === 'localhost' ||
            hostname === '127.0.0.1' ||
            hostname === '::1'
          ) return false
          // Check DNS resolution for IP addresses (can be CNAME to internal IP)
          let addresses: string[] = []
          try {
            // Supports both IPv4 and IPv6
            const result4 = await dns.resolve4(hostname).catch(() => [])
            const result6 = await dns.resolve6(hostname).catch(() => [])
            addresses = [...result4, ...result6]
          } catch (err) {
            return false // failed to resolve, treat as unsafe
          }
          if (addresses.length === 0) return false // No resolved addresses
          if (addresses.some(ip => isPrivateIp(ip))) return false
          // Check if the host is in the allow-list (allow subdomains)
          if (ALLOWED_IMAGE_HOSTS.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
            return true
          }
          return false
        } catch (err) {
          return false
        }
      }
      if (loggedInUser) {
        try {
          if (!(await isSafeImageUrl(url))) {
            res.status(400).send({ error: 'Invalid image URL. Only trusted image hosts are allowed.' })
            return
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
