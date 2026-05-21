package com.bbn.marti.maplayer.api;


import java.rmi.RemoteException;
import java.util.Collection;

import com.bbn.marti.maplayer.MapLayerService;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.bbn.marti.cot.search.model.ApiResponse;
import com.bbn.marti.maplayer.model.MapLayer;
import com.bbn.marti.network.BaseRestController;

import tak.server.Constants;


/*
 *
 * REST API for adding and retrieving Map Layers.
 *
 */
@RestController
public class MapLayersApi extends BaseRestController {

    // Cap on /maplayers/all response size. GET is ROLE_ANONYMOUS in
    // security-context.xml -- any authenticated caller can request the full
    // collection. Without a bound the server allocates and serializes every
    // map layer in the DB per request (CWE-400, CWE-770).
    public static final int MAX_MAP_LAYERS_PER_RESPONSE = Integer.getInteger(
            "tak.maplayer.maxPerResponse", 1000);

    /** Returns true if a layer set must be truncated. Extracted for unit tests. */
    public static boolean shouldTruncateMapLayers(int size, int cap) {
        return size > cap;
    }

	@Autowired
    private MapLayerService mapLayerService;

    /*
     * Get all Map Layers
     */
    @RequestMapping(value = "/maplayers/all", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    ApiResponse<Collection<MapLayer>> getAllMapLayers() throws RemoteException {

        Collection<MapLayer> all = mapLayerService.getAllMapLayers();
        if (all != null && shouldTruncateMapLayers(all.size(), MAX_MAP_LAYERS_PER_RESPONSE)) {
            java.util.List<MapLayer> truncated = new java.util.ArrayList<>(MAX_MAP_LAYERS_PER_RESPONSE);
            int i = 0;
            for (MapLayer ml : all) {
                if (i++ >= MAX_MAP_LAYERS_PER_RESPONSE) break;
                truncated.add(ml);
            }
            all = truncated;
        }
        return new ApiResponse<Collection<MapLayer>>(Constants.API_VERSION, MapLayer.class.getName(), all);
    }

    /*
     * Create a Map Layer
     */
    @RequestMapping(value = "/maplayers", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.OK)
    ApiResponse<MapLayer> createMapLayer(@RequestBody MapLayer mapLayer) {
        return new ApiResponse<>(Constants.API_VERSION, "MapLayer", mapLayerService.createMapLayer(mapLayer));
    }

    /*
     * Get Map Layer per uid
     */
    @RequestMapping(value = "/maplayers/{uid}", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    ApiResponse<MapLayer> getMapLayerForUid(@PathVariable("uid") @NotNull String uid) throws RemoteException {
        return new ApiResponse<>(Constants.API_VERSION, "MapLayer",
                mapLayerService.getMapLayerForUid(uid));
    }

    /*
     * Delete a Map Layer for a uid
     */
    @RequestMapping(value = "/maplayers/{uid}", method = RequestMethod.DELETE)
    public void deleteMapLayer(@PathVariable("uid") @NotNull String uid) throws RemoteException {
        mapLayerService.deleteMapLayer(uid);
    }

    /**
     * Update a map layer
     * @param modMapLayer
     * @return Updated MapLayer
     * @throws RemoteException
     */
    @RequestMapping(value = "/maplayers", method = RequestMethod.PUT)
    ApiResponse<MapLayer> updateMapLayer(@RequestBody MapLayer modMapLayer) throws RemoteException {
        return new ApiResponse<>(Constants.API_VERSION, "MapLayer", mapLayerService.updateMapLayer(modMapLayer));
    }
}