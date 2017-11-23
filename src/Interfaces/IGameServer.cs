﻿// <copyright file="IGameServer.cs" company="MUnique">
// Licensed under the MIT License. See LICENSE file in the project root for full license information.
// </copyright>

namespace MUnique.OpenMU.Interfaces
{
    using System;
    using System.Collections.Generic;
    using MUnique.OpenMU.DataModel.Configuration;
    using MUnique.OpenMU.DataModel.Entities;

    /// <summary>
    /// The state of the server.
    /// </summary>
    public enum ServerState
    {
        /// <summary>
        /// The server is currenctly starting, but has not yet finished initialization.
        /// </summary>
        Starting,

        /// <summary>
        /// The server started and is available.
        /// </summary>
        Started,

        /// <summary>
        /// The server is not available anymore and is stopping it's services.
        /// </summary>
        Stopping,

        /// <summary>
        /// The server has finished stopping.
        /// </summary>
        Stopped
    }

    /// <summary>
    /// Types of messages.
    /// </summary>
    public enum MessageType
    {
        /// <summary>
        /// The message is shown as centered golden message in the client.
        /// </summary>
        GoldenCenter = 0,

        /// <summary>
        /// The message is shown as blue entry.
        /// </summary>
        BlueNormal = 1
    }

    /// <summary>
    /// Interface for the inter-server communication.
    /// </summary>
    public interface IGameServer : IManageableServer
    {
        /// <summary>
        /// Gets the server information.
        /// </summary>
        IGameServerInfo ServerInfo { get; }

        /// <summary>
        /// Sends a chat message to all connected guild members.
        /// </summary>
        /// <param name="guildId">The guild identifier.</param>
        /// <param name="sender">The sender character name.</param>
        /// <param name="message">The message which should be sent.</param>
        void GuildChatMessage(Guid guildId, string sender, string message);

        /// <summary>
        /// Notifies the game server that a guild got deleted.
        /// </summary>
        /// <param name="guildId">The guild identifier.</param>
        void GuildDeleted(Guid guildId);

        /// <summary>
        /// Notifies the game server that a guild member got removed from a guild.
        /// </summary>
        /// <param name="playerName">Name of the player which got removed from a guild.</param>
        void GuildPlayerKicked(string playerName);

        /// <summary>
        /// Sends a chat message to all connected alliance members.
        /// </summary>
        /// <param name="guildID">The guild identifier.</param>
        /// <param name="sender">The sender character name.</param>
        /// <param name="message">The message.</param>
        void AllianceChatMessage(Guid guildID, string sender, string message);

        /// <summary>
        /// Notifies the game server that a letter got received for an online player.
        /// </summary>
        /// <param name="letter">The letter header.</param>
        void LetterReceived(LetterHeader letter);

        /// <summary>
        /// Determines whether the player with the specified name is online.
        /// </summary>
        /// <param name="playerName">Name of the character.</param>
        /// <returns>True, if online; False, otherwise.</returns>
        bool IsPlayerOnline(string playerName);

        /// <summary>
        /// Determines whether the account with the specified name is online.
        /// </summary>
        /// <param name="accountName">Name of the account.</param>
        /// <returns>True, if online; False, otherwise.</returns>
        bool IsAccountOnline(string accountName);

        /// <summary>
        /// Sends a global message to all connected players with the specified message type.
        /// </summary>
        /// <param name="message">The message.</param>
        /// <param name="messageType">Type of the message.</param>
        void SendGlobalMessage(string message, MessageType messageType);

        /// <summary>
        /// Notifies the server that a player made a friend request to another player, which is online on this server.
        /// </summary>
        /// <param name="requester">The requester.</param>
        /// <param name="receiver">The receiver.</param>
        void FriendRequest(string requester, string receiver);

        /// <summary>
        /// Notifies the game server that a friend online state changed.
        /// </summary>
        /// <param name="player">The player who is playing on the server, and needs to get notified.</param>
        /// <param name="friend">The friend whose state changed.</param>
        /// <param name="serverId">The new server identifier of the <paramref name="friend"/>.</param>
        void FriendOnlineStateChanged(string player, string friend, int serverId);

        /// <summary>
        /// Notifies the game server that a chat room got created on the chat server for a player which is online on this game server.
        /// </summary>
        /// <param name="playerAuthenticationInfo">Authentication information of the player who should get notified about the created chat room.</param>
        /// <param name="friendName">Name of the friend player which is expected to be in the chat room.</param>
        void ChatRoomCreated(ChatServerAuthenticationInfo playerAuthenticationInfo, string friendName);

        /// <summary>
        /// Registers an observers to a game map.
        /// </summary>
        /// <param name="mapId">The id of the map.</param>
        /// <param name="worldObserver">The world observer.</param>
        void RegisterMapObserver(ushort mapId, object worldObserver);

        /// <summary>
        /// Unregisters the map observer.
        /// </summary>
        /// <param name="mapId">The map identifier.</param>
        /// <param name="worldObserverId">The world observer identifier.</param>
        void UnregisterMapObserver(ushort mapId, ushort worldObserverId);
    }

    /// <summary>
    /// Informations about a game server.
    /// </summary>
    public interface IGameServerInfo
    {
        /// <summary>
        /// Gets the identifier.
        /// </summary>
        byte Id { get; }

        /// <summary>
        /// Gets the description.
        /// </summary>
        string Description { get; }

        /// <summary>
        /// Gets the state.
        /// </summary>
        ServerState State { get; }

        /// <summary>
        /// Gets the online player count.
        /// </summary>
        int OnlinePlayerCount { get; }

        /// <summary>
        /// Gets the maximum number of players.
        /// </summary>
        int MaximumPlayers { get; }

        /// <summary>
        /// Gets the maps which are hosted on this server.
        /// </summary>
        IList<IGameMapInfo> Maps { get; }
    }

    /// <summary>
    /// Information about a concrete instance of a game map.
    /// </summary>
    public interface IGameMapInfo
    {
        /// <summary>
        /// Gets the map definition.
        /// </summary>
        GameMapDefinition Map { get; }

        /// <summary>
        /// Gets the players which are currently playing on the map.
        /// </summary>
        IList<IPlayerInfo> Players { get; }
    }

    /// <summary>
    /// Information about a player.
    /// </summary>
    public interface IPlayerInfo
    {
        /// <summary>
        /// Gets the host adress.
        /// </summary>
        string HostAdress { get; }

        /// <summary>
        /// Gets the name of the character.
        /// </summary>
        string CharacterName { get; }

        /// <summary>
        /// Gets the name of the account.
        /// </summary>
        string AccountName { get; }

        /// <summary>
        /// Gets the x coordinate on the game map.
        /// </summary>
        byte LocationX { get; }

        /// <summary>
        /// Gets the y coordinate on the game map.
        /// </summary>
        byte LocationY { get; }
    }
}