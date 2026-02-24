package com.bbn.marti.maplayer;


import java.util.List;
import java.util.Date;
import java.util.UUID;
import com.google.common.base.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import com.bbn.marti.maplayer.model.MapLayer;
import com.bbn.marti.maplayer.repository.MapLayerRepository;
import com.bbn.marti.remote.exception.ForbiddenException;
import com.bbn.marti.remote.exception.NotFoundException;
import com.bbn.marti.remote.exception.TakException;
import com.bbn.marti.sync.model.Mission;


public class MapLayerService {

    @Autowired
    MapLayerRepository mapLayerRepository;

    public List<MapLayer> getAllMapLayers() {
        return mapLayerRepository.findAllByMissionIsNull(Sort.by("name"));
    }

    public MapLayer createMapLayer(MapLayer mapLayer) {
        String uid = UUID.randomUUID().toString().replace("-", "");
        mapLayer.setUid(uid);
        mapLayer.setCreateTime(new Date());
        mapLayer.setModifiedTime(new Date());
        MapLayer newMapLayer;

        if (mapLayer.isDefaultLayer()) {
            mapLayerRepository.unsetDefault();
        }
        try {

            newMapLayer = mapLayerRepository.save(mapLayer);

        } catch (Exception e) {
            throw new TakException("exception in createMapLayer", e);
        }

        return newMapLayer;

    }

    public MapLayer getMapLayerForUid(String uid)  {
        if (Strings.isNullOrEmpty(uid)) {
            throw new IllegalArgumentException("UID must be specified");
        }
        MapLayer mapLayer = mapLayerRepository.findByUidNoMission(uid);

        if (mapLayer == null) {
            throw new NotFoundException("no map layer stored for uid " + uid);
        }

        return mapLayer;
    }

    public void deleteMapLayer(String uid) {

        if (Strings.isNullOrEmpty(uid)) {
            throw new IllegalArgumentException("UID must be specified");
        }
        try {
            mapLayerRepository.deleteByUid(uid);
        } catch (Exception e) {
            throw new TakException("exception in deleteMapLayer", e);
        }
    }

    public void validateMapLayerBelongsToMission(String mapLayerUid, Mission mission) {
        MapLayer record = mapLayerRepository.findByUid(mapLayerUid);
        if (record == null) {
            throw new NotFoundException("no map layer stored for uid " + mapLayerUid);
        }
        Mission layerMission = record.getMission();
        if (mission == null && layerMission != null) {
            throw new ForbiddenException("map layer " + mapLayerUid + " belongs to a mission and cannot be modified in this context");
        }
        if (mission != null) {
            if (layerMission == null || !mission.getId().equals(layerMission.getId())) {
                throw new ForbiddenException("map layer " + mapLayerUid + " does not belong to mission " + mission.getName());
            }
        }
    }

    public MapLayer updateMapLayer(MapLayer modMapLayer)  {
        MapLayer updatedMapLayer; // result set returned
        String uid = modMapLayer.getUid();
        try {
            MapLayer record = mapLayerRepository.findByUid(uid);
            if (record == null) {
                throw new NotFoundException("no map layer stored for uid " + uid);
            }
            // if the new layer is the default, unset all the others
            if (modMapLayer.isDefaultLayer()) {
                mapLayerRepository.unsetDefault();
            }
            record.setCreatorUid(modMapLayer.getCreatorUid());
            record.setName(modMapLayer.getName());
            record.setDescription(modMapLayer.getDescription());
            record.setType(modMapLayer.getType());
            record.setUrl(modMapLayer.getUrl());
            record.setModifiedTime(new Date());
            record.setDefaultLayer(modMapLayer.isDefaultLayer());
            record.setEnabled(modMapLayer.isEnabled());

            updatedMapLayer = mapLayerRepository.save(record);
        } catch (Exception e) {
            throw new TakException("exception in updateMapLayer", e);
        }

        return updatedMapLayer;
    }
}